# Verity Netlify demo package

This package deploys the browser UI on Netlify and the Python analysis API as a separate Render web service. Netlify does not run this project's Python/OCR engine. The static page alone is not able to analyze documents until the API has been deployed and its URL configured.

## Included

- `netlify-site/`: static upload-ready frontend for Netlify Drop.
- `python-backend/`: FastAPI analyzer plus Dockerfile for Render.
- `render.yaml`: Render Blueprint for the backend.

The backend includes OCR (Tesseract), PDF/image metadata and existing local checks. PaddleOCR and research-model runners are not bundled in this cloud demo. Without issuer/signed-document verification, the app may return Unable to Verify or Suspicious — Review Required; it must not call a document genuine or fake based only on visual heuristics.

## Deploy the Python API to Render

1. Extract this ZIP.
2. Create a private GitHub repository and upload the extracted package contents, including `render.yaml` and `python-backend`. Do not upload real documents, `.env` files, database files, or model weights.
3. In Render, choose **New → Blueprint**, connect that repository, and deploy the `verity-document-review-api` service from `render.yaml`.
4. Copy the API service URL, such as `https://your-api.onrender.com`.
5. After the Netlify site is deployed, set the Render service environment variable `CORS_ALLOW_ORIGINS` to the exact Netlify origin (for example `https://your-site.netlify.app`, no trailing slash), replacing the placeholder, then redeploy the API.
6. Open `https://YOUR-API.onrender.com/api/health`; expect `{"ok":true,...}`.

## Configure and deploy the Netlify site

1. Open `netlify-site/config.js` in a text editor.
2. Set `window.VERITY_API_BASE` to your API URL with no trailing slash, e.g. `window.VERITY_API_BASE = 'https://your-api.onrender.com';`.
3. In Netlify, choose **Add new site → Deploy manually** and drag the extracted `netlify-site` folder (the folder containing `index.html`, `config.js`, and `_headers`) onto the deploy area. If updating an existing site, redeploy the folder after changing `config.js`.
4. Copy the assigned Netlify URL and apply it to Render's `CORS_ALLOW_ORIGINS`, then redeploy the API.
5. Open the Netlify URL and test with a small fictional sample. A sleeping demo API can take a little time to start.

## Demo privacy limits

Use fictional/test documents only on a public demo. Uploads are sent to the API host configured above. The demo has no login; anyone who can reach it may submit files. The API removes original temporary uploads after analysis, but retains extracted report/history data for the configured retention period. This starter uses temporary SQLite storage; history may be lost on service restart/redeploy. Do not upload real identity, medical, financial, or confidential documents. Add authentication, protected persistent storage, malware scanning, stronger isolation, monitoring, and a reviewed retention policy before real users.

## Local use

The original project remains runnable locally. From its project folder, run `\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8080`, then visit `http://127.0.0.1:8080`.
