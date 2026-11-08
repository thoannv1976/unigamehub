#!/usr/bin/env bash
# Deploys UniGame Hub to Cloud Run.
# Usage: deploy/deploy-cloudrun.sh [service-name]   (default: unigame-hub)
# Env: GAMES_ENABLED=demo,k26game1 (enabled games), GAME_URLS="GAME_LAUNCH_URL_K26GAME1=https://…|GAME_LAUNCH_URL_X=…"
# Secrets must already exist in Secret Manager: hub-signing-keys, hub-admin-token, game-secret-<id>.
set -euo pipefail
PROJECT="${PROJECT:-gamehub-514101}"
REGION="${REGION:-asia-southeast1}"
SERVICE="${1:-unigame-hub}"
SA="unigame-hub@${PROJECT}.iam.gserviceaccount.com"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' | tr -d '\r')"
BASE_URL="${HUB_BASE_URL:-https://${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app}"

# One GAME_SECRET_<ID> env var per game secret that exists.
GAME_SECRETS=""
for s in $(gcloud secrets list --project="$PROJECT" --filter='name~game-secret-' --format='value(name.basename())' | tr -d '\r'); do
  id="${s#game-secret-}"
  var="GAME_SECRET_$(echo "$id" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9\n' '_')"
  GAME_SECRETS+=",${var}=${s}:latest"
done

cd "$(dirname "$0")/.."
gcloud run deploy "$SERVICE" --quiet \
  --project="$PROJECT" --region="$REGION" --source=. \
  --service-account="$SA" \
  --allow-unauthenticated \
  --min-instances=0 --max-instances=5 --memory=512Mi --cpu=1 --concurrency=80 --timeout=60 \
  --set-env-vars="^|^HUB_ENV=prod|HUB_STORE=firestore|FIRESTORE_PROJECT=${PROJECT}|HUB_BASE_URL=${BASE_URL}|HUB_SELF_URL=${BASE_URL}|GAMES_ENABLED=${GAMES_ENABLED:-demo}${GAME_URLS:+|${GAME_URLS}}" \
  --set-secrets="HUB_SIGNING_KEYS=hub-signing-keys:latest,ADMIN_TOKEN=hub-admin-token:latest${GAME_SECRETS}"

echo "Deployed: ${BASE_URL}"
