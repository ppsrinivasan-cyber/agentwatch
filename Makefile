.PHONY: up down run scan test eval data watch
up:        ## start dashboard + mock webhook (Docker)
	docker compose up --build
down:
	docker compose down
run:       ## run without Docker (dashboard on :8080, built-in webhook receiver)
	python3 -m agentwatch.server
scan:      ## CLI dashboard over the sample log
	python3 -m agentwatch.cli scan data/sample_agent_activity.ndjson
watch:     ## live CLI dashboard against a running server
	python3 -m agentwatch.cli watch
test:
	python3 -m unittest discover -s tests -v
eval:
	python3 scripts/evaluate.py
data:      ## regenerate the sample dataset
	python3 scripts/generate_sample_data.py
