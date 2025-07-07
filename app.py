import os
import json
import redis
import time
import logging
from flask import Flask, request, jsonify
import pandas as pd
from sqlalchemy import create_engine
from dotenv import load_dotenv
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = os.environ.get("REDIS_PORT")

try:
    redis_client = redis.Redis(
    host=os.environ.get("REDIS_HOST", "redis_cache"),
    port=int(os.environ.get("REDIS_PORT", 6379)))
    redis_client.ping()
except redis.ConnectionError as e:
    logger.warning(f"Redis connection failed: {e}. Proceeding without cache.")
    redis_client = None

engine = create_engine(
    f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
    pool_size=20,
    max_overflow=10,
    pool_timeout=30
)

app = Flask(__name__)

@app.route('/fraud-check', methods=['POST'])
def fraud_check():
    start_time = time.time()
    request_data = request.json or {}
    user_ids = request_data.get("userIds", [])
    withdrawal_requests = request_data.get("withdrawalRequests", {})
    if not user_ids:
        return jsonify({"error": "No userIds provided"}), 400

    user_ids = [str(uid) for uid in user_ids]
    cache_key = f"fraud_check:{':'.join(sorted(user_ids))}"
    
    if redis_client:
        try:
            cache_start = time.time()
            cached_result = redis_client.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit: {time.time() - cache_start:.3f}s, key: {cache_key}")
                return jsonify(json.loads(cached_result))
        except redis.ConnectionError as e:
            logger.warning(f"Redis error during cache check: {e}")

    user_ids_tuple = tuple(user_ids)
    placeholders = ','.join(['%s'] * len(user_ids))

    combined_query = f'''
    SELECT 
        us."userId", us."totalDeposit", us."totalWithdraw",
        u."id" AS user_id, u."bankAccountNumber",
        s."userId" AS scrutiny_user_id, 
        s."lastDepositAmount", 
        s."totalBetAfterLastDeposit", 
        s."lastDepositAt",
        CASE 
            WHEN s."lastDepositAmount" > 0 
            AND s."totalBetAfterLastDeposit" < 0.5 * s."lastDepositAmount" 
            THEN TRUE 
            ELSE FALSE 
        END AS bet_rolling_violation,
        l."userId" AS login_user_id, l."ip", l."loggedInAt"
    FROM dashboard."UserStats" us
    LEFT JOIN public."User" u ON us."userId" = u."id"
    LEFT JOIN public."Scrutiny" s ON us."userId" = s."userId"
    LEFT JOIN public."LoginHistory" l ON us."userId" = l."userId"
    WHERE us."userId" IN ({placeholders})
    '''

    outlier_query = f'''
    SELECT 
        "userId",
        amount,
        "gameAt",
        "tranType"
    FROM public."MatkaTransaction"
    WHERE "userId" IN ({placeholders})
    AND "gameAt" >= CURRENT_DATE - INTERVAL '14 days'
    AND "tranType" IN ('BET', 'win')
    ORDER BY "gameAt" DESC
    LIMIT 100
    '''

    query_start = time.time()
    with engine.connect() as conn:
        combined_df = pd.read_sql(combined_query, conn, params=user_ids_tuple)
        outlier_df = pd.read_sql(outlier_query, conn, params=user_ids_tuple)
    logger.info(f"Query execution time: {time.time() - query_start:.3f}s")

    combined_df = combined_df.astype({
        'totalDeposit': 'float32',
        'totalWithdraw': 'float32',
        'lastDepositAmount': 'float32',
        'totalBetAfterLastDeposit': 'float32',
        'userId': 'str',
        'user_id': 'str',
        'scrutiny_user_id': 'str',
        'login_user_id': 'str'
    })
    outlier_df = outlier_df.astype({
        'userId': 'str',
        'amount': 'float32'
    })
    outlier_df['gameAt'] = pd.to_datetime(outlier_df['gameAt'], errors='coerce', utc=True)

    user_alerts = {}
    user_scores = {}
    related_users_map = {}

    def update_user_score(uid, reason, score, related=[]):
        user_alerts.setdefault(uid, []).append(reason)
        current = user_scores.get(uid, 0)
        user_scores[uid] = max(current, score)
        if related:
            related_users_map[uid] = related_users_map.get(uid, []) + related

    pandas_start = time.time()
    combined_df["netFloat"] = combined_df["totalDeposit"] - combined_df["totalWithdraw"]
    float_df = combined_df[combined_df["netFloat"] < -100000]
    for uid in float_df["userId"]:
        update_user_score(uid, "Net float < -₹1L", 5)

    bank_user_map = combined_df[combined_df["user_id"].isin(user_ids)].groupby("bankAccountNumber")["user_id"].agg(list).reset_index()
    shared_banks = bank_user_map[bank_user_map["user_id"].apply(len) > 1]
    for _, row in shared_banks.iterrows():
        users = row["user_id"]
        for user in users:
            others = [u for u in users if u != user]
            update_user_score(user, "Shared bank account", 8, others)

    combined_df['loggedInAt'] = pd.to_datetime(combined_df['loggedInAt'], errors='coerce', utc=True)
    ip_map = combined_df[combined_df["login_user_id"].isin(user_ids)].groupby("ip")["login_user_id"].agg(list).reset_index()
    shared_ips = ip_map[ip_map["login_user_id"].apply(len) > 1]
    for _, row in shared_ips.iterrows():
        users = row["login_user_id"]
        for user in users:
            others = [u for u in users if u != user]
            update_user_score(user, "Shared IP address", 5, others)

    violations = combined_df[combined_df['bet_rolling_violation'] == True]
    for uid in violations['scrutiny_user_id']:
        update_user_score(str(uid), "50% bet rolling not met after deposit", 4)

    for uid in user_ids:
        if str(uid) in withdrawal_requests and withdrawal_requests[str(uid)]:
            user_txns = outlier_df[outlier_df['userId'] == uid]
            if not user_txns.empty:
                non_winning_bets = user_txns[user_txns['tranType'] == 'BET']['amount']
                avg_bet = non_winning_bets.mean() if not non_winning_bets.empty else 0
                recent_win = user_txns[user_txns['tranType'] == 'win'].head(1)
                if not recent_win.empty:
                    recent_win_amount = recent_win['amount'].iloc[0]
                    if avg_bet > 0 and recent_win_amount >= 3 * avg_bet:
                        update_user_score(uid, "Outlier win (≥300% of average) in last 14 days", 8)

    logger.info(f"Pandas processing time: {time.time() - pandas_start:.3f}s")

    def get_risk(score):
        if score >= 8:
            return "Red"
        elif score >= 5:
            return "Yellow"
        else:
            return "Green"

    now = datetime.utcnow().isoformat()
    alerts = []
    for uid in user_alerts:
        alerts.append({
            "userId": uid,
            "alertReasons": ", ".join(sorted(set(user_alerts[uid]))),
            "alertTime": now,
            "relatedUserIds": ", ".join(sorted(set(map(str, related_users_map.get(uid, []))))),
            "fraudScore": user_scores[uid],
            "riskLevel": get_risk(user_scores[uid])
        })

    if redis_client:
        try:
            redis_client.setex(cache_key, 10800, json.dumps({"alerts": alerts}, separators=(',', ':')))
            logger.info(f"Cache set for key: {cache_key}")
        except redis.ConnectionError as e:
            logger.warning(f"Redis error during cache set: {e}")

    logger.info(f"Total execution time: {time.time() - start_time:.3f}s")
    return jsonify({"alerts": alerts})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)