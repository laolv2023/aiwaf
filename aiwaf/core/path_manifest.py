"""
路径清单 (Path Manifest) — 从 Kafka 流量自动构建

替代官方仓库中基于 Django/Flask 路由的 path_manifest.py。
通过分析历史流量的 HTTP 响应，自动归纳 URL 模板，
用于 path_exists() 判定和关键词学习的合法路径过滤。

工作原理：
  1. 每条流量处理后，URL 模板化（/api/users/123 → /api/users/{id}）
  2. 记录到 Redis：aiwaf:paths:{template} → {count, ok_count, status_codes}
  3. path_exists(path) = 模板化后检查 Redis 中是否存在且 2xx 比例 > 50%
  4. 定期清理低频路径（防膨胀）

模块化设计：
  - PathManifest: 纯逻辑层，不依赖 Redis（可独立测试）
  - RedisPathManifestStore: Redis 持久化层
  - templify_path(): URL → 模板（整数/UUID/长十六进制 → 占位符）
"""
import re
import time
import hashlib
import orjson
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict


# ── URL 模板化规则 ──

# 整数段：纯数字 → {id}
_INT_RE = re.compile(r'^\d+$')

# UUID：550e8400-e29b-41d4-a716-446655440000 → {uuid}
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# 长十六进制（≥16字符）：SHA256/MD5 等 → {hex}
_LONG_HEX_RE = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)

# Base64 编码（≥20字符，含 +/=）： → {b64}
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

# 长随机字符串（≥32字符，混合大小写+数字）
_LONG_RANDOM_RE = re.compile(r'^(?=[A-Za-z0-9]{32,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')

# 哈希前缀（常见 JWT/session token 开头）
_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


def templify_path(path: str) -> str:
    """
    将具体 URL 路径转换为模板。

    /api/users/123          → /api/users/{id}
    /api/orders/550e8400-...  → /api/orders/{uuid}
    /api/files/a1b2c3d4e5f6... → /api/files/{hex}
    /api/v1/search           → /api/v1/search  (无变化)
    /                       → /

    规则按优先级：
      1. UUID → {uuid}
      2. JWT → {jwt}
      3. 纯整数 → {id}
      4. 长十六进制 (≥16) → {hex}
      5. Base64 (≥20) → {b64}
      6. 长随机串 (≥32) → {token}
    """
    if not path or path == "/":
        return "/"

    # 拆分路径段
    parts = path.strip("/").split("/")
    result_parts = []

    for part in parts:
        if not part:
            continue

        # 1. UUID
        if _UUID_RE.match(part):
            result_parts.append("{uuid}")
        # 2. JWT
        elif _JWT_RE.match(part):
            result_parts.append("{jwt}")
        # 3. 纯整数
        elif _INT_RE.match(part):
            result_parts.append("{id}")
        # 4. 长十六进制
        elif _LONG_HEX_RE.match(part):
            result_parts.append("{hex}")
        # 5. Base64
        elif _B64_RE.match(part):
            result_parts.append("{b64}")
        # 6. 长随机串
        elif _LONG_RANDOM_RE.match(part):
            result_parts.append("{token}")
        else:
            result_parts.append(part)

    return "/" + "/".join(result_parts)


# ── 数据结构 ──

@dataclass
class PathStats:
    """单条路径模板的统计信息"""
    template: str
    total_count: int = 0
    ok_count: int = 0       # 2xx 响应数
    error_count: int = 0     # 4xx/5xx 响应数
    methods: Set[str] = field(default_factory=set)
    last_seen: float = 0.0

    @property
    def ok_ratio(self) -> float:
        return self.ok_count / max(self.total_count, 1)

    @property
    def is_known(self) -> bool:
        """路径是否被视为"已知"：至少 3 次访问且 2xx 比例 > 50%"""
        return self.total_count >= 3 and self.ok_ratio > 0.5


# ── 纯逻辑层（可独立测试）──

class PathManifest:
    """
    路径清单管理器（内存版本，可独立测试）。

    生产环境使用 RedisPathManifestStore 持久化。
    """

    def __init__(self):
        self._paths: Dict[str, PathStats] = {}

    def record(self, path: str, method: str, status_code: int, timestamp: float = None):
        """记录一条流量"""
        template = templify_path(path)
        ts = timestamp or time.time()

        if template not in self._paths:
            self._paths[template] = PathStats(template=template)

        stats = self._paths[template]
        stats.total_count += 1
        stats.methods.add(method.upper())
        stats.last_seen = ts

        if 200 <= status_code < 300:
            stats.ok_count += 1
        elif status_code >= 400:
            stats.error_count += 1

    def path_exists(self, path: str) -> bool:
        """判定路径是否为已知合法路径"""
        template = templify_path(path)
        stats = self._paths.get(template)
        return stats.is_known if stats else False

    def get_stats(self, path: str) -> Optional[PathStats]:
        template = templify_path(path)
        return self._paths.get(template)

    def get_all_templates(self) -> List[str]:
        return list(self._paths.keys())

    def cleanup(self, min_count: int = 2, max_age_seconds: int = 86400, now: float = None):
        """清理低频/过期路径（防膨胀）"""
        now = now or time.time()
        to_remove = [
            tpl for tpl, stats in self._paths.items()
            if stats.total_count < min_count
            or (now - stats.last_seen) > max_age_seconds
        ]
        for tpl in to_remove:
            del self._paths[tpl]
        return len(to_remove)

    def to_dict(self) -> Dict[str, dict]:
        """序列化为可 JSON 化的 dict"""
        return {
            tpl: {
                "total": s.total_count,
                "ok": s.ok_count,
                "error": s.error_count,
                "methods": sorted(s.methods),
                "last_seen": s.last_seen,
            }
            for tpl, s in self._paths.items()
        }

    def from_dict(self, data: Dict[str, dict]):
        """从 dict 反序列化"""
        for tpl, d in data.items():
            stats = PathStats(template=tpl)
            stats.total_count = d.get("total", 0)
            stats.ok_count = d.get("ok", 0)
            stats.error_count = d.get("error", 0)
            stats.methods = set(d.get("methods", []))
            stats.last_seen = d.get("last_seen", 0)
            self._paths[tpl] = stats


# ── Redis 持久化层 ──

class RedisPathManifestStore:
    """
    Redis 持久化的路径清单存储。

    Redis 结构：
      Hash: aiwaf:paths → {template: JSON统计}
      Key : aiwaf:paths:updated → 最后更新时间
    """

    def __init__(self, redis_facade):
        """redis_facade: RedisStateFacade 或兼容的异步 Redis 客户端"""
        self._redis = redis_facade

    async def record(self, path: str, method: str, status_code: int, timestamp: float = None):
        """异步记录一条流量到 Redis"""
        template = templify_path(path)
        ts = timestamp or time.time()
        key = f"aiwaf:paths:{template}"

        # 使用 Redis Hash 存储统计
        pipe = self._redis.redis.pipeline()
        pipe.hincrby(key, "total", 1)
        if 200 <= status_code < 300:
            pipe.hincrby(key, "ok", 1)
        elif status_code >= 400:
            pipe.hincrby(key, "error", 1)
        pipe.hset(key, "last_seen", str(ts))
        pipe.sadd(f"{key}:methods", method.upper())
        pipe.expire(key, 86400 * 7)  # 7 天过期
        pipe.expire(f"{key}:methods", 86400 * 7)
        await pipe.execute()

    async def path_exists(self, path: str) -> bool:
        """异步判定路径是否为已知合法路径"""
        template = templify_path(path)
        key = f"aiwaf:paths:{template}"
        data = await self._redis.redis.hgetall(key)

        if not data:
            return False

        total = int(data.get("total", 0))
        ok = int(data.get("ok", 0))
        return total >= 3 and (ok / max(total, 1)) > 0.5

    async def get_all_templates(self) -> List[str]:
        """获取所有已知路径模板"""
        # 扫描所有 aiwaf:paths:* key
        templates = []
        async for key in self._redis.redis.scan_iter(match="aiwaf:paths:*", count=100):
            # key 格式: aiwaf:paths:/api/users/{id}  或  aiwaf:paths:/api/users/{id}:methods
            k = key.decode() if isinstance(key, bytes) else key
            if k.endswith(":methods"):
                continue
            template = k.replace("aiwaf:paths:", "", 1)
            templates.append(template)
        return templates

    async def cleanup(self, min_count: int = 2, max_age_seconds: int = 86400):
        """清理低频/过期路径"""
        now = time.time()
        to_delete = []
        async for key in self._redis.redis.scan_iter(match="aiwaf:paths:*", count=100):
            k = key.decode() if isinstance(key, bytes) else key
            if k.endswith(":methods"):
                continue
            data = await self._redis.redis.hgetall(k)
            if not data:
                to_delete.append(k)
                continue
            total = int(data.get("total", 0))
            last_seen = float(data.get("last_seen", 0))
            if total < min_count or (now - last_seen) > max_age_seconds:
                to_delete.append(k)
                to_delete.append(f"{k}:methods")

        if to_delete:
            await self._redis.redis.delete(*to_delete)
        return len(to_delete)
