import django_rq
from apps.main.tasks import microsoftEntraIDUserSyncTask

# Get the scheduler for the default queue
scheduler = django_rq.get_scheduler('default')

# Schedule job to run every hour (cron format: minute hour day month day_of_week)
# '0 * * * *' means: at minute 0 of every hour
job = scheduler.cron(
    cron_string='0 * * * *',  # Every hour at minute 0
    func=microsoftEntraIDUserSyncTask,
    args=('system@tierzerocode.com', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Chrome', 'Windows'),
    job_id='microsoft_entra_id_user_sync_hourly',  # Unique ID to prevent duplicates
    replace=True  # Replace existing job with same ID if it exists
)