#!/usr/bin/env python3
"""Test MobSF API key fetching"""
import asyncio
from app.services.mobsf_client import MobSFClient

async def test():
    client = MobSFClient()
    key = await client._fetch_api_key()
    print(f"Got API key: {key}")
    return key

if __name__ == "__main__":
    asyncio.run(test())
