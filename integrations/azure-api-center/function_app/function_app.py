"""Azure Functions（Python v2 モデル）の入口。

タイマーで定期的に台帳を確認し、「未審査」のMCPサーバを maGATE で審査して結果を書き戻す。
実行間隔はアプリ設定 MAGATE_SCHEDULE（NCRONTAB 形式。例：15分ごと "0 */15 * * * *"）。
"""
import logging

import azure.functions as func

from apic_client import ApiCenterClient
from reviewer import run_once

app = func.FunctionApp()


@app.timer_trigger(schedule="%MAGATE_SCHEDULE%", arg_name="timer", run_on_startup=False)
def magate_review(timer: func.TimerRequest) -> None:
    for line in run_once(ApiCenterClient.from_env()):
        logging.info("maGATE: %s", line)
