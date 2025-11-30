import os
import redis

url = os.environ["REDIS_URL"]  # must be set
r = redis.Redis.from_url(url, decode_responses=True)

print("PING:", r.ping())
print("First keys:", list(r.scan_iter("*"))[:50])
