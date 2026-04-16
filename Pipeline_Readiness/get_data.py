import os

import requests
import configparser
import logging
from logging.handlers import RotatingFileHandler

# ---------------- LOGGING SETUP ----------------
LOG_FILE = "cast_campaign.log"
ERROR_LOG_FILE = "cast_campaign_errors.log"

logger = logging.getLogger("CAST_CAMPAIGN")
logger.setLevel(logging.DEBUG)

fmt = "%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)d] %(message)s"
formatter = logging.Formatter(fmt)

console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

error_handler = RotatingFileHandler(ERROR_LOG_FILE, maxBytes=2_000_000, backupCount=2)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)


# ---------------- CONFIG ----------------
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.properties'))

BASE_URL = config['creds']['hl_instance']
DOMAIN_ID = config['creds']['domain_id']
TOKEN = config['creds']['token']

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

CAMPAIGN_NAME = " Pipeline_Readiness"
from datetime import datetime,timedelta

current_date = datetime.now().strftime("%Y-%m-%d")
CAMPAIGN_NAME="{}_{}".format(CAMPAIGN_NAME,current_date)
CLOSING_DATE = (datetime.now() + timedelta(weeks=2)).strftime("%Y-%m-%d")

# ---------------- HELPERS (404 SAFE) ----------------
def get_json(api):
    try:
        logger.debug(f"GET  {api}")
        r = requests.get(api, headers=HEADERS)

        if r.status_code == 404:
            logger.warning(f"404 Not Found   {api}")
            return None

        r.raise_for_status()
        logger.debug(f"GET Success   {api}")
        return r.json()

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error  {api} | {e} | Response: {r.text}")
        return None

    except Exception:
        logger.exception(f"Unexpected error   {api}")
        return None


def post_json(api, payload):
    try:
        logger.debug(f"POST  {api}")
        logger.debug(f"Payload {payload}")

        r = requests.post(api, json=payload, headers=HEADERS)
        r.raise_for_status()

        logger.info(f"POST Success  {api}")
        return r.json() if r.text else {}

    except Exception:
        logger.exception(f"POST failed  {api}")
        return {}


# ---------------- APPLICATIONS ----------------
def get_applications():
    api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/applications"
    logger.info("Fetching applications list")
    apps = get_json(api) or []
    logger.info(f"Applications fetched: {len(apps)}")
    return apps


# ---------------- TECH STACK (.NET / JDK) ----------------
def get_tech_stack(app_id):
    logger.debug(f"Fetching tech stack for app_id={app_id}")
    api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/applications/{app_id}/applicationData"
    resp = get_json(api) or []

    result = {'.NET':'No','JDK':'NO'}
    for item in resp:
        name = item.get("name")
        ver = item.get("version")
        if name=='.NET':
            result['.NET']='YES'
        elif name=='JDK':
            result['JDK']='YES'
        # if name not in ('.NET', 'JDK'):
        #     continue
        #
        # if name not in result:
        #     result[name] = ver
        #     continue
        #
        # try:
        #     if ver and result[name] and version.parse(ver) > version.parse(result[name]):
        #         result[name] = ver
        # except Exception:
        #     logger.warning(f"Version compare failed for {name}: {ver}")

    logger.debug(f"Tech stack  {result},{resp}")
    return result


# ---------------- DEPRECATED + KEV ----------------
def analyze_app(app_id, app_name):
    logger.info(f"Analyzing app  {app_name} ({app_id})")

    api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/applications/{app_id}/thirdparty"
    data = get_json(api) or {}
    resp = data.get("thirdParties", [])

    lifespan = 'Yes' if any(i.get('lifeSpan') == 'PossiblyDeprecated' for i in resp) else 'No'

    iskev = 'No'
    for comp in resp:
        vulns = comp.get('cve', {}).get('vulnerabilities', [])
        if any(v.get('isKev') for v in vulns):
            iskev = 'Yes'
            break

    tech = get_tech_stack(app_id)

    result = {
        "App_Name": app_name,
        "App_Id": app_id,
        "lifespan": lifespan,
        "iskev": iskev,
        "tech_stack": tech
    }

    logger.info(f"Analysis complete   {result}")
    return result


# ---------------- GET PIPELINE 2.0 SURVEY ----------------
def get_pipeline_survey():
    logger.info("Fetching 'Pipeline 2.0' survey")
    api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/surveys"
    surveys = get_json(api) or []
    survey = next(s for s in surveys if s.get("name") == "Pipeline 2.0")
    logger.info(f"Survey found  id={survey['id']}")
    return survey


# ---------------- CREATE CAMPAIGN ----------------
def create_campaign(apps, survey):
    api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/campaigns"
    payload = [{
        "name": CAMPAIGN_NAME,
        "closingDate": CLOSING_DATE,
        "applications": [{"id": a["App_Id"], "name": a["App_Name"]} for a in apps],
        "surveys": [{
            "id": survey["id"],
            "name": survey["name"],
            "ref": "CAST_APP",
            "castPrivateSurvey": True,
            "questions": []
        }],
        "status": "started",
        "requestScan": False,
        "requestSurvey": True,
        "sendMessage": False,
    }]

    logger.debug(f"Campaign payload  {payload}")
    post_json(api, payload)


# ---------------- BUILD SURVEY PAYLOAD ----------------
def build_payload(questions, app):
    logger.debug(f"Building payload for  {app['App_Name']}")
    answers = []

    for q in questions:
        label_lower = q["label"].lower()

        if q["type"] != "tag":
            continue

        # -------- Decide answer text --------
        if "deprecated components" in label_lower:
            ans = app["lifespan"]

        elif "kev" in label_lower:
            ans = app["iskev"]

        elif ".net framework?" in label_lower:
            ans = str(app["tech_stack"].get(".NET", "NO"))

        elif "java technology?" in label_lower:
            ans = str(app["tech_stack"].get("JDK", "NO"))

        else:
            continue

        # -------- Map to choice id --------
        choice_id = next(
            c["id"] for c in q["choice"]
            if c["label"].strip().lower() == ans.strip().lower()
        )

        answers.append({
            "questionId": q["id"],
            "questionRef": q["label"],
            "value": choice_id,
            "values": [],
            "incomingLinks": [0],
            "outgoingLinks": [0]
        })

    return answers


# ---------------- POST & SUBMIT SURVEY ----------------
def post_surveys(apps, survey):
    logger.info("Posting surveys for all applications")

    camp_api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/campaigns"
    campaigns = get_json(camp_api) or []
    camp_id = next(c["id"] for c in campaigns if c["name"] == CAMPAIGN_NAME)


    for app in apps:
        logger.info(f"Submitting survey  {app['App_Name']}")

        app_id = app["App_Id"]
        survey_api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/applications/{app_id}/campaigns/{camp_id}/surveys/{survey['id']}"
        submit_api = f"{BASE_URL}/WS2/domains/{DOMAIN_ID}/applications/{app_id}/campaigns/{camp_id}/submit"

        payload = build_payload(survey["questions"], app)
        logger.debug(f"Survey payload  {payload}")

        post_json(survey_api, payload)
        post_json(submit_api, {})


# ---------------- MAIN ----------------
if __name__ == "__main__":
    logger.info("===== CAST Campaign Automation Started =====")

    applications = get_applications()
    logger.info(f"Total applications: {len(applications)}")

    analyzed_apps = [
        analyze_app(a["id"], a["name"])
        for a in applications
    ]

    survey = get_pipeline_survey()
    #
    create_campaign(analyzed_apps, survey)

    post_surveys(analyzed_apps, survey)

    logger.info("===== All surveys processed without stopping on 404 =====")
