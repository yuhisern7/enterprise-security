
docker exec battle-hardened-ai python -c "from AI.crypto_security import get_message_security; import json; s=get_message_security(); m=s.sign_message({'attack_type':'TEST_HMAC','src_ip':'1.2.3.4'}); print(json.dumps(m, indent=2)); print('\nHas HMAC:', 'hmac' in m)"

docker compose logs relay-server | grep -E "HMAC|Shared|secret"

