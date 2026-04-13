from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def normalize_repo_url(url: str | None) -> str | None:
    if not url:
        return None

    url = url.strip()
    if not url:
        return None

    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.strip().strip("/")
    if not host or not path:
        return None

    if path.endswith(".git"):
        path = path[:-4]

    path = path.strip("/")
    if not path:
        return None

    return f"{host}/{path.lower()}"


def normalize_project_key(name: str | None) -> str | None:
    if not name:
        return None
    key = re.sub(r"[^a-z0-9]+", "", name.lower())
    return key or None


def extract_github_slug(url: str | None) -> str | None:
    repo_key = normalize_repo_url(url)
    if not repo_key:
        return None
    if not repo_key.startswith("github.com/"):
        return None
    return repo_key.split("/", 1)[1]


@dataclass(frozen=True)
class ProjectInfo:
    name: str
    main_repo_url: str | None
    repo_key: str | None
    github_slug: str | None
    language: str | None
    package_aliases: tuple[str, ...]


class ProjectResolver:
    """Resolve source-specific project names and repo URLs to Vuljector names."""

    # These aliases are only accepted when they are also repo-compatible.
    _REPO_VALIDATED_ALIASES: dict[str, str] = {
        "arrow": "arrow-py",
        "libfmt": "fmt",
        "sql-parser": "sqlparse",
        "uWebSockets": "uwebsockets",
        "FreeRDP": "freerdp",
        "cJSON": "cjson",
        "php-src": "php",
        "zlib": "zlib-ng",
    }

    def __init__(self, projects: dict[str, ProjectInfo]) -> None:
        self.projects = projects
        self._by_name = {name.lower(): name for name in projects}
        self._by_repo = {
            info.repo_key: info.name
            for info in projects.values()
            if info.repo_key
        }
        self._by_normalized_name = {
            normalize_project_key(info.name): info.name
            for info in projects.values()
            if normalize_project_key(info.name)
        }
        alias_to_projects: dict[str, set[str]] = {}
        normalized_alias_to_projects: dict[str, set[str]] = {}
        for info in projects.values():
            for alias in info.package_aliases:
                alias_key = alias.lower()
                alias_to_projects.setdefault(alias_key, set()).add(info.name)
                normalized = normalize_project_key(alias)
                if normalized:
                    normalized_alias_to_projects.setdefault(normalized, set()).add(info.name)
        self._by_alias = {
            alias: next(iter(projects_for_alias))
            for alias, projects_for_alias in alias_to_projects.items()
            if len(projects_for_alias) == 1
        }
        self._by_normalized_alias = {
            alias: next(iter(projects_for_alias))
            for alias, projects_for_alias in normalized_alias_to_projects.items()
            if len(projects_for_alias) == 1
        }

    @classmethod
    def from_projects_dir(cls, projects_dir: Path) -> "ProjectResolver":
        projects: dict[str, ProjectInfo] = {}
        for proj_json in sorted(projects_dir.glob("*/project.json")):
            try:
                data = json.loads(proj_json.read_text())
            except Exception:
                continue

            name = data.get("project")
            if not name:
                continue

            main_repo_url = data.get("main_repo_url")
            github_slug = extract_github_slug(main_repo_url)
            language = data.get("language")
            extra_aliases = [proj_json.parent.name]
            target_dir = data.get("target_dir")
            if target_dir:
                extra_aliases.append(str(target_dir))
            projects[name] = ProjectInfo(
                name=name,
                main_repo_url=main_repo_url,
                repo_key=normalize_repo_url(main_repo_url),
                github_slug=github_slug,
                language=language,
                package_aliases=tuple(
                    _derive_package_aliases(
                        name,
                        main_repo_url,
                        github_slug=github_slug,
                        extra_aliases=extra_aliases,
                    )
                ),
            )

        return cls(projects)

    @classmethod
    def from_csv_rows(cls, rows: list[dict]) -> "ProjectResolver":
        projects: dict[str, ProjectInfo] = {}
        for row in rows:
            name = row.get("name")
            if not name:
                continue

            main_repo_url = row.get("main_repo") or row.get("main_repo_url")
            github_slug = row.get("github_slug") or extract_github_slug(main_repo_url)
            language = row.get("language")
            extra_aliases = []
            target_dir = row.get("target_dir")
            if target_dir:
                extra_aliases.append(str(target_dir))
            projects[name] = ProjectInfo(
                name=name,
                main_repo_url=main_repo_url,
                repo_key=normalize_repo_url(main_repo_url),
                github_slug=github_slug,
                language=language,
                package_aliases=tuple(
                    _derive_package_aliases(
                        name,
                        main_repo_url,
                        github_slug=github_slug,
                        extra_aliases=extra_aliases,
                    )
                ),
            )

        return cls(projects)

    @classmethod
    def from_csv_path(cls, csv_path: Path) -> "ProjectResolver":
        import csv

        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        return cls.from_csv_rows(rows)

    def project_names(self) -> set[str]:
        return set(self.projects)

    def get_project(self, name: str) -> ProjectInfo | None:
        return self.projects.get(name)

    def iter_projects(self) -> list[ProjectInfo]:
        return list(self.projects.values())

    def resolve(self, raw_name: str | None, repo_url: str | None = None) -> str | None:
        project, _ = self.resolve_with_reason(raw_name, repo_url)
        return project

    def resolve_with_reason(
        self,
        raw_name: str | None,
        repo_url: str | None = None,
    ) -> tuple[str | None, str | None]:
        repo_key = normalize_repo_url(repo_url)

        # Repo URL is the strongest signal when present.
        if repo_key and repo_key in self._by_repo:
            return self._by_repo[repo_key], "repo"

        if not raw_name:
            return None, None

        # Exact shortlist name.
        exact = self._by_name.get(raw_name.lower())
        if exact and self._repo_compatible(exact, repo_key):
            return exact, "exact_name"

        # Explicit aliases that still require repo compatibility when available.
        alias_target = self._REPO_VALIDATED_ALIASES.get(raw_name)
        if alias_target and alias_target in self.projects:
            if self._repo_compatible(alias_target, repo_key):
                return alias_target, "validated_alias"

        alias = self._by_alias.get(raw_name.lower())
        if alias and self._repo_compatible(alias, repo_key):
            return alias, "unique_alias"

        # Normalized-name fallback for cases like behavior-treecpp vs behaviortreecpp.
        normalized = normalize_project_key(raw_name)
        if normalized and normalized in self._by_normalized_name:
            candidate = self._by_normalized_name[normalized]
            if self._repo_compatible(candidate, repo_key):
                return candidate, "normalized_name"

        if normalized and normalized in self._by_normalized_alias:
            candidate = self._by_normalized_alias[normalized]
            if self._repo_compatible(candidate, repo_key):
                return candidate, "normalized_alias"

        return None, None

    def _repo_compatible(self, project_name: str, repo_key: str | None) -> bool:
        if repo_key is None:
            return True

        project = self.projects.get(project_name)
        if project is None or project.repo_key is None:
            return True

        return project.repo_key == repo_key


def _derive_package_aliases(
    name: str,
    main_repo_url: str | None,
    github_slug: str | None = None,
    extra_aliases: list[str] | None = None,
) -> list[str]:
    aliases: set[str] = set()
    aliases.add(name)

    normalized_name = name.replace("-", "_")
    aliases.add(normalized_name)
    aliases.add(name.replace("_", "-"))

    repo_key = normalize_repo_url(main_repo_url)
    if repo_key:
        repo_path = repo_key.split("/", 1)[1]
        basename = repo_path.rsplit("/", 1)[-1]
        if basename:
            aliases.add(basename)
            aliases.add(basename.replace("-", "_"))
            aliases.add(basename.replace("_", "-"))

    if github_slug:
        slug = github_slug.strip().strip("/")
        if slug:
            aliases.add(slug)
            basename = slug.rsplit("/", 1)[-1]
            aliases.add(basename)
            aliases.add(basename.replace("-", "_"))
            aliases.add(basename.replace("_", "-"))

    for alias in extra_aliases or []:
        if not alias:
            continue
        alias = str(alias).strip()
        if not alias:
            continue
        aliases.add(alias)
        aliases.add(alias.replace("-", "_"))
        aliases.add(alias.replace("_", "-"))

    return sorted(a for a in aliases if a)
