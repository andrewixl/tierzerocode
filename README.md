<a href="https://github.com/andrewixl/tierzerocode/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/andrewixl/tierzerocode"></a>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/andrewixl/tierzerocode">
<a href="https://github.com/andrewixl/tierzerocode/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/andrewixl/tierzerocode"></a>

# Tier Zero C.O.D.E (Tier Zero Correlation of Distributed Endpoints)

## Minimum Requirements
- [ ] 4 GB RAM

## Getting started

Docker Install: Latest
```bash
andrewixl/tierzerocode:latest
```

Docker Install: Latest - Dev
```bash
andrewixl/tierzerocode:latest-dev
```

Port 8000

## Production Deployment with Docker Compose

### Option 1: Full Stack (Web + Worker + Database + Redis)

This setup runs everything in Docker Compose, including PostgreSQL and Redis:

1. Create a `.env` file with your configuration:
```bash
SECRET_KEY=your-secret-key-here
DEBUG=False
DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_NAME=dockerdjango
DATABASE_USER=dbuser
DATABASE_PASSWORD=dbpassword
GUNICORN_WORKERS=3
WEB_PORT=8000
```

2. Pull and start all services:
```bash
docker-compose pull
docker-compose up -d
```

3. Run migrations:
```bash
docker-compose exec web python manage.py migrate
```

4. Create superuser (if needed):
```bash
docker-compose exec web python manage.py createsuperuser
```

### Option 2: Production (External Database/Redis)

If you have external database and Redis services, use `docker-compose.prod.yml`:

1. Create a `.env` file:
```bash
SECRET_KEY=your-secret-key-here
DEBUG=False
DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_HOST=your-db-host.com
DATABASE_NAME=your_db_name
DATABASE_USER=your_db_user
DATABASE_PASSWORD=your_db_password
DATABASE_PORT=5432
REDIS_HOST=your-redis-host.com
REDIS_PORT=6379
GUNICORN_WORKERS=3
WEB_PORT=8000
```

2. Start services:
```bash
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

### Managing Services

- View logs: `docker-compose logs -f web` or `docker-compose logs -f worker`
- Stop services: `docker-compose down`
- Restart a service: `docker-compose restart web`
- Scale workers: Edit `docker-compose.yml` and use `docker-compose up -d --scale worker=3`

### Image Tags

The docker-compose files use `docker.io/andrewixl/tierzerocode:latest` by default. To use a specific version:
```yaml
image: docker.io/andrewixl/tierzerocode:v1.0.0
```

## Required Permissions per Integration
- CrowdStrike Falcon
    - Hosts - Read
- Microsoft Defender for Endpoint
    - WindowsDefenderATP - Machine.Read.All - Application Permissions
- Microsoft Entra ID
    - Microsoft Graph - Device.Read.All
    - Microsoft Graph - AuditLog.Read.All
- Microsoft Intune
    - Microsoft Graph - DeviceManagementManagedDevices.Read.All
- Sophos Central
    - API Credential - Service Principal Management Role

## Integrate with your tools

- [ ] Cloudflare Zero Trust
- [ ] CrowdStrike Falcon
- [ ] Microsoft Defender for Endpoint
- [ ] Microsoft Entra ID
- [ ] Microsoft Intune
- [ ] Sophos Central
- [ ] Qualys Vulnerability Management (Limited to First 1000 Devices)

## Roadmap
- [ ] Qualys Vulnerability Management (All Devices)
- [ ] JAMF Pro (Under Development)
- [ ] Tenable (Under Development)

## Support
Please sumbit any issues into the issues section within this GitHub

## Contribute
If you are feeling generous, love the project, or just want to show your appreciation please donated at the Patreon Link Below!
https://www.patreon.com/tierzerocode

<!-- ## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!). Thanks to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers. -->
