"""
Continuous Validation Integration for Intellicrack.

Provides automated validation testing integrated with CI/CD pipelines,
real-time monitoring, and automated reporting for continuous assessment
of Intellicrack's effectiveness against modern protections.
"""

import os
import sys
import json
import yaml
import time
import subprocess
import threading
import queue
import socket
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections.abc import Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
import asyncio
import aiohttp
import schedule
import jenkins
import github
import gitlab
import requests
from prometheus_client import Counter, Gauge, Histogram, Summary, start_http_server
from influxdb import InfluxDBClient
import redis
import psutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import telegram
from discord_webhook import DiscordWebhook, DiscordEmbed


class TriggerType(Enum):
    """Types of triggers for validation runs."""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    TAG = "tag"
    API = "api"
    WEBHOOK = "webhook"
    FILE_CHANGE = "file_change"


class ValidationStatus(Enum):
    """Status of validation run."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class ValidationJob:
    """Represents a validation job in the pipeline."""
    job_id: str
    trigger_type: TriggerType
    trigger_data: dict
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    status: ValidationStatus = ValidationStatus.PENDING
    phases_to_run: list[str] = field(default_factory=list)
    results: dict = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    error_message: str | None = None
    retry_count: int = 0


class MetricsCollector:
    """Collects and exports metrics for monitoring."""

    def __init__(self, port: int = 8000):
        self.port = port

        # Prometheus metrics
        self.validation_runs = Counter(
            'intellicrack_validation_runs_total',
            'Total number of validation runs',
            ['trigger_type', 'status']
        )

        self.validation_duration = Histogram(
            'intellicrack_validation_duration_seconds',
            'Duration of validation runs',
            ['phase']
        )

        self.protection_bypass_rate = Gauge(
            'intellicrack_protection_bypass_rate',
            'Success rate for protection bypass',
            ['protection_type']
        )

        self.test_success_rate = Gauge(
            'intellicrack_test_success_rate',
            'Overall test success rate'
        )

        self.active_jobs = Gauge(
            'intellicrack_active_validation_jobs',
            'Number of active validation jobs'
        )

        # Start metrics server
        start_http_server(self.port)

    def record_run(self, trigger_type: str, status: str):
        """Record validation run."""
        self.validation_runs.labels(
            trigger_type=trigger_type,
            status=status
        ).inc()

    def record_duration(self, phase: str, duration: float):
        """Record phase duration."""
        self.validation_duration.labels(phase=phase).observe(duration)

    def update_bypass_rate(self, protection_type: str, rate: float):
        """Update protection bypass rate."""
        self.protection_bypass_rate.labels(
            protection_type=protection_type
        ).set(rate)

    def update_success_rate(self, rate: float):
        """Update overall success rate."""
        self.test_success_rate.set(rate)

    def update_active_jobs(self, count: int):
        """Update active job count."""
        self.active_jobs.set(count)


class NotificationManager:
    """Manages notifications across multiple channels."""

    def __init__(self, config: dict):
        self.config = config
        self.channels = []

        # Initialize notification channels
        if config.get("slack"):
            self.slack_client = WebClient(token=config["slack"]["token"])
            self.slack_channel = config["slack"]["channel"]
            self.channels.append("slack")

        if config.get("discord"):
            self.discord_webhook_url = config["discord"]["webhook_url"]
            self.channels.append("discord")

        if config.get("telegram"):
            self.telegram_bot = telegram.Bot(token=config["telegram"]["token"])
            self.telegram_chat_id = config["telegram"]["chat_id"]
            self.channels.append("telegram")

        if config.get("email"):
            self.email_config = config["email"]
            self.channels.append("email")

    def send_notification(
        self,
        title: str,
        message: str,
        level: str = "info",
        attachments: list[dict] = None
    ):
        """Send notification to all configured channels."""

        # Slack notification
        if "slack" in self.channels:
            self._send_slack(title, message, level, attachments)

        # Discord notification
        if "discord" in self.channels:
            self._send_discord(title, message, level)

        # Telegram notification
        if "telegram" in self.channels:
            self._send_telegram(title, message, level)

        # Email notification
        if "email" in self.channels:
            self._send_email(title, message, level)

    def _send_slack(self, title: str, message: str, level: str, attachments: list[dict]):
        """Send Slack notification."""
        try:
            color = {
                "info": "#36a64f",
                "warning": "#ff9900",
                "error": "#ff0000",
                "success": "#00ff00"
            }.get(level, "#808080")

            slack_attachments = [{
                "color": color,
                "title": title,
                "text": message,
                "footer": "Intellicrack Validation",
                "ts": int(time.time())
            }]

            if attachments:
                slack_attachments.extend(attachments)

            self.slack_client.chat_postMessage(
                channel=self.slack_channel,
                attachments=slack_attachments
            )
        except SlackApiError as e:
            print(f"Slack notification failed: {e}")

    def _send_discord(self, title: str, message: str, level: str):
        """Send Discord notification."""
        try:
            webhook = DiscordWebhook(url=self.discord_webhook_url)

            color = {
                "info": 0x3498db,
                "warning": 0xff9900,
                "error": 0xff0000,
                "success": 0x00ff00
            }.get(level, 0x808080)

            embed = DiscordEmbed(
                title=title,
                description=message,
                color=color
            )
            embed.set_footer(text="Intellicrack Validation")
            embed.set_timestamp()

            webhook.add_embed(embed)
            webhook.execute()
        except Exception as e:
            print(f"Discord notification failed: {e}")

    def _send_telegram(self, title: str, message: str, level: str):
        """Send Telegram notification."""
        try:
            icon = {
                "info": "i",
                "warning": "WARNING",
                "error": "FAIL",
                "success": "OK"
            }.get(level, "📢")

            text = f"{icon} *{title}*\n\n{message}"

            self.telegram_bot.send_message(
                chat_id=self.telegram_chat_id,
                text=text,
                parse_mode="Markdown"
            )
        except Exception as e:
            print(f"Telegram notification failed: {e}")

    def _send_email(self, title: str, message: str, level: str):
        """Send email notification."""
        try:
            msg = MIMEMultipart()
            msg["From"] = self.email_config["from"]
            msg["To"] = ", ".join(self.email_config["to"])
            msg["Subject"] = f"[Intellicrack {level.upper()}] {title}"

            body = f"""
            <html>
            <body>
                <h2>{title}</h2>
                <p>{message}</p>
                <hr>
                <p><small>Intellicrack Validation System</small></p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"]) as server:
                if self.email_config.get("use_tls"):
                    server.starttls()
                if self.email_config.get("username"):
                    server.login(self.email_config["username"], self.email_config["password"])
                server.send_message(msg)
        except Exception as e:
            print(f"Email notification failed: {e}")


class CIPlatformIntegration:
    """Integration with CI/CD platforms."""

    def __init__(self, platform: str, config: dict):
        self.platform = platform
        self.config = config
        self.client = self._initialize_client()

    def _initialize_client(self):
        """Initialize platform-specific client."""
        if self.platform == "jenkins":
            return jenkins.Jenkins(
                self.config["url"],
                username=self.config.get("username"),
                password=self.config.get("password")
            )
        elif self.platform == "github":
            return github.Github(self.config["token"])
        elif self.platform == "gitlab":
            return gitlab.Gitlab(
                self.config["url"],
                private_token=self.config["token"]
            )

    def trigger_validation(self, trigger_data: dict) -> str:
        """Trigger validation job on CI platform."""
        if self.platform == "jenkins":
            return self._trigger_jenkins(trigger_data)
        elif self.platform == "github":
            return self._trigger_github_action(trigger_data)
        elif self.platform == "gitlab":
            return self._trigger_gitlab_pipeline(trigger_data)

    def _trigger_jenkins(self, trigger_data: dict) -> str:
        """Trigger Jenkins job."""
        job_name = self.config["job_name"]
        parameters = {
            "TRIGGER_TYPE": trigger_data.get("type", "manual"),
            "BRANCH": trigger_data.get("branch", "main"),
            "PHASES": ",".join(trigger_data.get("phases", ["all"]))
        }

        queue_item = self.client.build_job(job_name, parameters)
        return f"jenkins_{queue_item}"

    def _trigger_github_action(self, trigger_data: dict) -> str:
        """Trigger GitHub Action workflow."""
        repo = self.client.get_repo(self.config["repository"])
        workflow = repo.get_workflow(self.config["workflow_id"])

        workflow.create_dispatch(
            ref=trigger_data.get("branch", "main"),
            inputs={
                "trigger_type": trigger_data.get("type", "manual"),
                "phases": ",".join(trigger_data.get("phases", ["all"]))
            }
        )

        return f"github_{workflow.id}_{int(time.time())}"

    def _trigger_gitlab_pipeline(self, trigger_data: dict) -> str:
        """Trigger GitLab pipeline."""
        project = self.client.projects.get(self.config["project_id"])

        pipeline = project.pipelines.create({
            "ref": trigger_data.get("branch", "main"),
            "variables": [
                {"key": "TRIGGER_TYPE", "value": trigger_data.get("type", "manual")},
                {"key": "PHASES", "value": ",".join(trigger_data.get("phases", ["all"]))}
            ]
        })

        return f"gitlab_{pipeline.id}"

    def get_job_status(self, job_id: str) -> dict:
        """Get status of CI job."""
        if self.platform == "jenkins":
            return self._get_jenkins_status(job_id)
        elif self.platform == "github":
            return self._get_github_status(job_id)
        elif self.platform == "gitlab":
            return self._get_gitlab_status(job_id)

    def _get_jenkins_status(self, job_id: str) -> dict:
        """Get Jenkins job status."""
        # Parse job_id to get queue number
        queue_num = int(job_id.split("_")[1])

        try:
            build_info = self.client.get_queue_item(queue_num)
            if build_info.get("executable"):
                build = build_info["executable"]
                return {
                    "status": build["result"],
                    "url": build["url"],
                    "duration": build["duration"]
                }
            else:
                return {"status": "PENDING"}
        except Exception:
            return {"status": "UNKNOWN"}


class ValidationScheduler:
    """Schedules and manages validation runs."""

    def __init__(self, config: dict):
        self.config = config
        self.jobs_queue = queue.Queue()
        self.active_jobs = {}
        self.completed_jobs = []
        self.scheduler_thread = None
        self.worker_threads = []
        self.stop_event = threading.Event()

    def start(self):
        """Start scheduler and workers."""
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._run_scheduler)
        self.scheduler_thread.start()

        # Start worker threads
        num_workers = self.config.get("num_workers", 2)
        for i in range(num_workers):
            worker = threading.Thread(target=self._worker, args=(i,))
            worker.start()
            self.worker_threads.append(worker)

        print(f"Validation scheduler started with {num_workers} workers")

    def _run_scheduler(self):
        """Run scheduled jobs."""
        # Set up schedules
        if self.config.get("schedules"):
            for schedule_config in self.config["schedules"]:
                self._setup_schedule(schedule_config)

        while not self.stop_event.is_set():
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    def _setup_schedule(self, schedule_config: dict):
        """Set up a scheduled job."""
        trigger_data = {
            "type": "scheduled",
            "schedule": schedule_config["name"],
            "phases": schedule_config.get("phases", ["all"])
        }

        if schedule_config["type"] == "daily":
            schedule.every().day.at(schedule_config["time"]).do(
                self.queue_job, TriggerType.SCHEDULED, trigger_data
            )
        elif schedule_config["type"] == "weekly":
            getattr(schedule.every(), schedule_config["day"]).at(
                schedule_config["time"]
            ).do(self.queue_job, TriggerType.SCHEDULED, trigger_data)
        elif schedule_config["type"] == "interval":
            schedule.every(schedule_config["interval"]).minutes.do(
                self.queue_job, TriggerType.SCHEDULED, trigger_data
            )

    def queue_job(self, trigger_type: TriggerType, trigger_data: dict) -> ValidationJob:
        """Queue a validation job."""
        job = ValidationJob(
            job_id=self._generate_job_id(),
            trigger_type=trigger_type,
            trigger_data=trigger_data,
            created_at=datetime.now(timezone.utc),
            phases_to_run=trigger_data.get("phases", ["all"])
        )

        self.jobs_queue.put(job)
        print(f"Queued validation job: {job.job_id}")

        return job

    def _generate_job_id(self) -> str:
        """Generate unique job ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.md5(os.urandom(16)).hexdigest()[:8]
        return f"val_{timestamp}_{random_suffix}"

    def _worker(self, worker_id: int):
        """Worker thread to process jobs."""
        print(f"Worker {worker_id} started")

        while not self.stop_event.is_set():
            try:
                # Get job from queue with timeout
                job = self.jobs_queue.get(timeout=1)

                print(f"Worker {worker_id} processing job: {job.job_id}")
                self.active_jobs[job.job_id] = job

                # Process job
                self._process_job(job)

                # Move to completed
                self.active_jobs.pop(job.job_id)
                self.completed_jobs.append(job)

                # Limit completed jobs history
                if len(self.completed_jobs) > 100:
                    self.completed_jobs = self.completed_jobs[-100:]

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker {worker_id} error: {e}")

    def _process_job(self, job: ValidationJob):
        """Process a validation job."""
        job.started_at = datetime.now(timezone.utc)
        job.status = ValidationStatus.RUNNING

        try:
            # Run validation
            from ..runner import ValidationRunner

            runner = ValidationRunner()
            results = runner.run_validation(
                phases=job.phases_to_run,
                config=job.trigger_data.get("config", {})
            )

            job.results = results
            job.status = ValidationStatus.SUCCESS if results["success"] else ValidationStatus.FAILURE

        except Exception as e:
            job.status = ValidationStatus.ERROR
            job.error_message = str(e)

        finally:
            job.completed_at = datetime.now(timezone.utc)

    def stop(self):
        """Stop scheduler and workers."""
        self.stop_event.set()

        if self.scheduler_thread:
            self.scheduler_thread.join()

        for worker in self.worker_threads:
            worker.join()


class ContinuousValidationIntegration:
    """
    Main class for continuous validation integration with CI/CD pipelines,
    monitoring, and automated reporting.
    """

    def __init__(self, config_file: Path):
        self.config = self._load_config(config_file)
        self.metrics = MetricsCollector(
            port=self.config.get("metrics_port", 8000)
        )
        self.notifier = NotificationManager(
            self.config.get("notifications", {})
        )
        self.scheduler = ValidationScheduler(
            self.config.get("scheduler", {})
        )
        self.ci_integrations = self._setup_ci_integrations()
        self.api_server = None

    def _load_config(self, config_file: Path) -> dict:
        """Load configuration from file."""
        if config_file.suffix == ".json":
            with open(config_file) as f:
                return json.load(f)
        elif config_file.suffix in [".yml", ".yaml"]:
            with open(config_file) as f:
                return yaml.safe_load(f)
        else:
            raise ValueError(f"Unsupported config format: {config_file.suffix}")

    def _setup_ci_integrations(self) -> dict:
        """Set up CI platform integrations."""
        return {
            platform: CIPlatformIntegration(platform, config)
            for platform, config in self.config.get("ci_platforms", {}).items()
            if config.get("enabled")
        }

    async def start(self):
        """Start continuous validation system."""
        print("Starting Intellicrack Continuous Validation Integration")

        # Start scheduler
        self.scheduler.start()

        # Start API server
        await self._start_api_server()

        # Start webhook listeners
        await self._start_webhook_listeners()

        # Send startup notification
        self.notifier.send_notification(
            "Continuous Validation Started",
            f"System initialized with {len(self.ci_integrations)} CI integrations",
            level="info"
        )

        print("Continuous validation system running")

    async def _start_api_server(self):
        """Start REST API server for external triggers."""
        from aiohttp import web

        app = web.Application()

        # Define routes
        app.router.add_post("/api/v1/validation/trigger", self._handle_trigger)
        app.router.add_get("/api/v1/validation/status/{job_id}", self._handle_status)
        app.router.add_get("/api/v1/validation/jobs", self._handle_list_jobs)
        app.router.add_get("/api/v1/validation/metrics", self._handle_metrics)
        app.router.add_post("/api/v1/validation/webhook/{provider}", self._handle_webhook)

        # Start server
        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            self.config.get("api_host", "0.0.0.0"),
            self.config.get("api_port", 8080)
        )

        await site.start()
        self.api_server = runner

        print(f"API server started on {self.config.get('api_host')}:{self.config.get('api_port')}")

    async def _handle_trigger(self, request: web.Request) -> web.Response:
        """Handle validation trigger via API."""
        try:
            data = await request.json()

            # Validate request
            if "phases" not in data:
                return web.json_response(
                    {"error": "Missing required field: phases"},
                    status=400
                )

            # Queue job
            job = self.scheduler.queue_job(
                TriggerType.API,
                data
            )

            # Update metrics
            self.metrics.record_run("api", "triggered")

            return web.json_response({
                "job_id": job.job_id,
                "status": job.status.value,
                "created_at": job.created_at.isoformat()
            })

        except Exception as e:
            return web.json_response(
                {"error": str(e)},
                status=500
            )

    async def _handle_status(self, request: web.Request) -> web.Response:
        """Get job status via API."""
        job_id = request.match_info["job_id"]

        # Check active jobs
        if job_id in self.scheduler.active_jobs:
            job = self.scheduler.active_jobs[job_id]
        else:
            # Check completed jobs
            job = next((j for j in self.scheduler.completed_jobs if j.job_id == job_id), None)

        if not job:
            return web.json_response(
                {"error": "Job not found"},
                status=404
            )

        return web.json_response({
            "job_id": job.job_id,
            "status": job.status.value,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "results": job.results if job.status == ValidationStatus.SUCCESS else None,
            "error": job.error_message
        })

    async def _handle_list_jobs(self, request: web.Request) -> web.Response:
        """List validation jobs."""
        jobs = [
            {
                "job_id": job.job_id,
                "status": job.status.value,
                "trigger_type": job.trigger_type.value,
                "created_at": job.created_at.isoformat(),
            }
            for job in self.scheduler.active_jobs.values()
        ]
        # Add recent completed jobs
        jobs.extend(
            {
                "job_id": job.job_id,
                "status": job.status.value,
                "trigger_type": job.trigger_type.value,
                "created_at": job.created_at.isoformat(),
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
            }
            for job in self.scheduler.completed_jobs[-20:]
        )
        return web.json_response({"jobs": jobs})

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Get current metrics."""
        # This would integrate with Prometheus metrics
        return web.json_response({
            "active_jobs": len(self.scheduler.active_jobs),
            "completed_jobs": len(self.scheduler.completed_jobs),
            "queue_size": self.scheduler.jobs_queue.qsize()
        })

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        """Handle webhook from CI/CD platforms."""
        provider = request.match_info["provider"]

        try:
            if provider == "github":
                return await self._handle_github_webhook(request)
            elif provider == "gitlab":
                return await self._handle_gitlab_webhook(request)
            elif provider == "bitbucket":
                return await self._handle_bitbucket_webhook(request)
            else:
                return web.json_response(
                    {"error": f"Unknown provider: {provider}"},
                    status=400
                )
        except Exception as e:
            return web.json_response(
                {"error": str(e)},
                status=500
            )

    async def _handle_github_webhook(self, request: web.Request) -> web.Response:
        """Handle GitHub webhook."""
        headers = request.headers
        body = await request.read()

        # Verify signature
        if not self._verify_github_signature(headers, body):
            return web.json_response(
                {"error": "Invalid signature"},
                status=401
            )

        data = await request.json()
        event_type = headers.get("X-GitHub-Event")

        # Handle different event types
        if event_type == "push":
            # Trigger validation on push
            job = self.scheduler.queue_job(
                TriggerType.COMMIT,
                {
                    "repository": data["repository"]["full_name"],
                    "branch": data["ref"].split("/")[-1],
                    "commit": data["after"],
                    "author": data["pusher"]["name"]
                }
            )

            self.notifier.send_notification(
                "Validation Triggered",
                f"Push to {data['repository']['full_name']} triggered validation",
                level="info"
            )

        elif event_type == "pull_request":
            if data["action"] in ["opened", "synchronize"]:
                # Trigger validation on PR
                job = self.scheduler.queue_job(
                    TriggerType.PULL_REQUEST,
                    {
                        "repository": data["repository"]["full_name"],
                        "pr_number": data["pull_request"]["number"],
                        "branch": data["pull_request"]["head"]["ref"],
                        "author": data["pull_request"]["user"]["login"]
                    }
                )

        return web.json_response({"status": "ok"})

    def _verify_github_signature(self, headers: dict, body: bytes) -> bool:
        """Verify GitHub webhook signature."""
        signature = headers.get("X-Hub-Signature-256")
        if not signature:
            return False

        secret = self.config.get("webhooks", {}).get("github_secret", "").encode()
        expected = f"sha256={hmac.new(secret, body, hashlib.sha256).hexdigest()}"

        return hmac.compare_digest(signature, expected)

    async def _handle_gitlab_webhook(self, request: web.Request) -> web.Response:
        """Handle GitLab webhook."""
        headers = request.headers

        # Verify token
        token = headers.get("X-Gitlab-Token")
        expected_token = self.config.get("webhooks", {}).get("gitlab_token")

        if token != expected_token:
            return web.json_response(
                {"error": "Invalid token"},
                status=401
            )

        data = await request.json()
        event_type = data.get("object_kind")

        if event_type == "push":
            # Trigger validation on push
            job = self.scheduler.queue_job(
                TriggerType.COMMIT,
                {
                    "repository": data["project"]["path_with_namespace"],
                    "branch": data["ref"].split("/")[-1],
                    "commit": data["after"],
                    "author": data["user_name"]
                }
            )

        return web.json_response({"status": "ok"})

    async def _handle_bitbucket_webhook(self, request: web.Request) -> web.Response:
        """Handle Bitbucket webhook."""
        # Implementation for Bitbucket webhooks
        pass

    async def _start_webhook_listeners(self):
        """Start listening for webhooks from various sources."""
        # File system watcher for local triggers
        if self.config.get("watch_directories"):
            asyncio.create_task(self._watch_filesystem())

        # Redis pub/sub for distributed triggers
        if self.config.get("redis"):
            asyncio.create_task(self._listen_redis())

    async def _watch_filesystem(self):
        """Watch filesystem for changes that trigger validation."""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class ValidationTriggerHandler(FileSystemEventHandler):
            def __init__(self, scheduler):
                self.scheduler = scheduler

            def on_modified(self, event):
                if not event.is_directory:
                    # Check if file matches trigger patterns
                    for pattern in self.config.get("watch_patterns", []):
                        if Path(event.src_path).match(pattern):
                            self.scheduler.queue_job(
                                TriggerType.FILE_CHANGE,
                                {"file": event.src_path}
                            )
                            break

        observer = Observer()
        handler = ValidationTriggerHandler(self.scheduler)

        for directory in self.config.get("watch_directories", []):
            observer.schedule(handler, directory, recursive=True)

        observer.start()

    async def _listen_redis(self):
        """Listen for Redis pub/sub triggers."""
        redis_config = self.config.get("redis", {})
        r = redis.Redis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 0)
        )

        pubsub = r.pubsub()
        pubsub.subscribe(redis_config.get("channel", "intellicrack:validation"))

        for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    self.scheduler.queue_job(
                        TriggerType.API,
                        data
                    )
                except Exception:
                    pass
                    # Message parsing may fail, continue processing other messages

    async def stop(self):
        """Stop continuous validation system."""
        print("Stopping continuous validation system...")

        # Stop scheduler
        self.scheduler.stop()

        # Stop API server
        if self.api_server:
            await self.api_server.cleanup()

        # Send shutdown notification
        self.notifier.send_notification(
            "Continuous Validation Stopped",
            "System shutdown complete",
            level="info"
        )

        print("Continuous validation system stopped")


async def main():
    """Main entry point for continuous validation."""
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack Continuous Validation")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("continuous_validation_config.yml"),
        help="Configuration file path"
    )

    args = parser.parse_args()

    # Create default config if not exists
    if not args.config.exists():
        default_config = {
            "api_host": "0.0.0.0",
            "api_port": 8080,
            "metrics_port": 8000,
            "scheduler": {
                "num_workers": 2,
                "schedules": [
                    {
                        "name": "daily_validation",
                        "type": "daily",
                        "time": "02:00",
                        "phases": ["all"]
                    }
                ]
            },
            "notifications": {
                "slack": {
                    "enabled": False,
                    "token": "xoxb-your-token",
                    "channel": "#validation"
                }
            },
            "ci_platforms": {
                "jenkins": {
                    "enabled": False,
                    "url": "http://jenkins.example.com",
                    "job_name": "intellicrack-validation"
                }
            }
        }

        with open(args.config, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False)

        print(f"Created default config: {args.config}")

    # Start system
    integration = ContinuousValidationIntegration(args.config)

    try:
        await integration.start()

        # Keep running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        await integration.stop()


if __name__ == "__main__":
    asyncio.run(main())
