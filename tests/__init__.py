import os

# テストは 127.0.0.1 に模擬サーバを立てて通信するため、関所（magate/netguard.py）の
# プライベートアドレス拒否をテスト全体で解除する。関所そのもののテスト（test_netguard.py）は
# この設定を個別に外して確認する。本番の既定は「拒否」のまま。
os.environ.setdefault("MAGATE_ALLOW_PRIVATE", "1")
