"""配備の前に、maGATE 本体（magate/）と変換処理（writeback.py）をこのフォルダにコピーする。

  python integrations/azure-api-center/function_app/prepare.py
コピーしたものは .gitignore で除外している（正本はリポジトリの元の場所）。
"""
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

dst = os.path.join(HERE, "magate")
shutil.rmtree(dst, ignore_errors=True)
shutil.copytree(os.path.join(ROOT, "magate"), dst, ignore=shutil.ignore_patterns("__pycache__"))
shutil.copy2(os.path.join(HERE, "..", "writeback.py"), os.path.join(HERE, "writeback.py"))
print(f"コピーしました: {dst} と writeback.py")
