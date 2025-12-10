from django.apps import AppConfig


class MainConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'main'
    default = False
    
    def ready(self):
        # Import and register scheduled tasks when Django starts
        import apps.main.cron  # noqa: F401