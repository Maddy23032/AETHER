# Aether Insights

## How can I edit this code?

**Use your preferred IDE**

If you want to work locally using your own IDE, you can clone this repo and push changes.

The only requirement is having Node.js & npm installed - [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating)

Follow these steps:

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

You can deploy this Vite app to platforms like Vercel, Netlify, or GitHub Pages.

For example, to deploy to Vercel:

1. Push your code to GitHub.
2. Connect your repo to Vercel.
3. Deploy.

## Can I connect a custom domain?

Yes, most hosting platforms support custom domains. Check their documentation.

---

# Aether Insights: Security Platform

Aether is a full-stack, research-grade security analysis platform for web and mobile applications. It combines automated reconnaissance, vulnerability enumeration, mobile app analysis, and a novel **Dynamic Graph Sitemap** for infrastructure visualization, all powered by a context-aware AI chatbot.

## ✨ Key Features

- **Reconnaissance (Recon):**
  - Automated subdomain, DNS, port, and technology discovery
  - Integrates tools like Nmap, WhatWeb, Subfinder, Amass, DNSenum, etc.
  - Results are ingested into the graph and AI context

- **Enumeration:**
  - Deep vulnerability scanning (OWASP Top 10, custom checks)
  - Real-time scan progress, findings, and exportable reports
  - Results persist in Supabase and are available to the AI
  - Powerful filtering and search in the UI

- **Mobile Security:**
  - APK/IPA static analysis (permissions, trackers, components, security issues)
  - MobSF backend integration
  - Results are stored in Supabase and available to the AI

- **Intelligence Chatbot:**
  - RAG-powered assistant (FAISS + HuggingFace + Groq LLM)
  - Answers questions about all scans, vulnerabilities, and graph data
  - Context-aware: references real scan data, findings, and graph structure

- **Dynamic Graph Sitemap (Novel Research Contribution):**
  - Interactive, security-aware infrastructure graph
  - Visualizes domains, subdomains, IPs, endpoints, vulnerabilities, technologies, etc.
  - Novel algorithms: Security-Aware PageRank, Vulnerability Propagation, Functional Zone Clustering
  - Attack path analysis, risk scoring, and export (PNG, JSON, GEXF)
  - Fully integrated with scan ingestion and AI context

- **Dashboard:**
  - Real-time KPIs, scan/vulnerability trends, severity breakdowns
  - Top vulnerabilities, target summaries, mobile app summaries
  - All data is live from Supabase and backend APIs

- **Supabase Integration:**
  - All scans, vulnerabilities, and mobile results are persisted
  - Enables cross-service context and AI awareness

---

## 🏗️ Architecture Overview

- **Frontend:** React 18 + Vite + TypeScript + Tailwind + shadcn-ui + Cytoscape.js
- **Backend (Intelligence):** FastAPI (port 8002), RAG, Graph algorithms, AI endpoints
- **Backend (Recon):** FastAPI (port 8000), Recon tools, scan orchestration
- **Backend (Mobile):** FastAPI (port 3001), MobSF wrapper
- **Database:** Supabase PostgreSQL (scans, vulnerabilities, mobile_scans, graph tables)
- **Graph Processing:** NetworkX, custom algorithms (SA-PageRank, propagation, clustering)
- **AI:** Groq LLM, HuggingFace embeddings, FAISS vector store

---

## 🚀 Getting Started

### 1. Clone & Install
```sh
git clone <YOUR_GIT_URL>
cd <YOUR_PROJECT_NAME>
npm i
```

### 2. Start the Frontend
```sh
npm run dev
```

### 3. Start the Backends
- **Intelligence:**
  ```sh
  cd backend(intelligence)
  python -m uvicorn app.main:app --reload --port 8002
  ```
- **Recon:**
  ```sh
  cd backend(recon)
  python -m uvicorn app.main:app --reload --port 8000
  ```
- **Mobile:**
  ```sh
  cd backend(mobile)
  python -m uvicorn app.main:app --reload --port 3001
  ```

### 4. Environment Variables
- Set your Supabase, Groq, and MobSF keys in the respective `.env` files for each backend.

---

## 🧠 Feature Details

### Reconnaissance
- Launch scans from the Recon page
- View live logs, findings, and results
- All data is saved to Supabase and available for graph/AI

### Enumeration
- Start vulnerability scans with custom options
- Real-time progress, findings, and export (JSON, CSV, HTML)
- Filter and search vulnerabilities in the UI

### Mobile Security
- Upload APK/IPA for static analysis
- View permissions, trackers, security issues
- Results are saved and available to the AI

### Intelligence Chatbot
- Ask questions about any scan, vulnerability, or graph node
- Cites real data and provides context-aware answers
- Uses RAG (Retrieval Augmented Generation) with FAISS and Groq LLM

### Dynamic Graph Sitemap (Novelty)
- Create a session and ingest scans (Recon, Enum, Mobile)
- Visualize the infrastructure as an interactive graph
- Run advanced algorithms:
  - **Security-Aware PageRank:** Highlights critical nodes
  - **Vulnerability Propagation:** Shows risk spread
  - **Functional Zone Clustering:** Groups by business/security function
- Analyze attack paths, risk scores, and export the graph
- All graph data is available to the AI chatbot

### Dashboard
- Real-time KPIs, scan/vulnerability trends, severity breakdowns
- Top vulnerabilities, target summaries, mobile app summaries
- All data is live from Supabase and backend APIs

---

## 🗄️ Database Schema Highlights
- `scans`: All recon/enum scan metadata
- `vulnerabilities`: All findings from enumeration
- `mobile_scans`: Mobile app analysis results
- `graph_sessions`, `graph_nodes`, `graph_edges`, ...: Dynamic Graph Sitemap tables

---

## 📚 Research & Novelty
- **Dynamic Graph Sitemap** is a novel contribution:
  - Combines real scan data, advanced graph algorithms, and AI context
  - Enables new forms of security analysis and visualization
  - All algorithms and schema are documented in `algorithms.py` and `migration_add_graph_sitemap.sql`

---

## 📦 Deployment
- Deploy frontend to Vercel, Netlify, or similar
- Deploy backends to your preferred Python hosting (or locally)
- Supabase is managed in the cloud

---

## 🤝 Contributing
Pull requests and research collaborations are welcome!

---

## 📄 License
MIT

---
