#!/usr/bin/env python3
"""SaltVault Update Helper

Checks for updates in the current git repository (compares local branch to remote),
offers to pull changes, and creates a backup of the current working tree prior to pulling.

Safety features:
- Excludes databases, instance secrets, and environment/config files from being overwritten.
- Backup is a zip under `backups/backup-YYYYmmdd-HHMMSS.zip` with safe excludes.

Usage:
  python scripts/check_for_update.py
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIR = ROOT / 'backups'

# Paths/patterns to exclude from backup and protect from overwrite
PROTECT_PATHS = [
  'app/data',            # SQLite DBs
  'instance',            # Flask instance (secret_key)
  'app/app.env',         # Active env file
  'app/app.env.example', # Example env file (kept, but not critical)
  'nginx/certs',         # TLS certs
  'nginx/nginx.conf',    # Rendered config
]


def run(cmd, check=True):
  return subprocess.run(cmd, check=check, capture_output=True, text=True)


def ensure_git_repo():
  try:
    run(['git', '-C', str(ROOT), 'rev-parse', '--is-inside-work-tree'])
  except subprocess.CalledProcessError:
    print('This does not appear to be a git repository. Aborting.')
    sys.exit(1)


def get_branch():
  res = run(['git', '-C', str(ROOT), 'rev-parse', '--abbrev-ref', 'HEAD'])
  return res.stdout.strip()


def fetch_remote():
  print('Fetching remote updates...')
  run(['git', '-C', str(ROOT), 'fetch', 'origin'], check=True)


def ahead_behind(branch: str):
  """Return tuple (ahead, behind) counts relative to origin/<branch>."""
  # Ensure upstream tracking
  try:
    run(['git', '-C', str(ROOT), 'rev-parse', '--verify', f'origin/{branch}'])
  except subprocess.CalledProcessError:
    print(f"Remote branch origin/{branch} not found. Ensure 'origin' is set.")
    return (0, 0)
  res = run(['git', '-C', str(ROOT), 'rev-list', '--left-right', '--count', f'HEAD...origin/{branch}'])
  parts = res.stdout.strip().split()
  if len(parts) == 2:
    ahead, behind = map(int, parts)
    return (ahead, behind)
  return (0, 0)


def make_backup():
  """Create a zip backup of the working tree excluding protected paths and existing backups.
  Uses a manual zip walk to avoid including the new archive itself and to skip large / sensitive paths.
  """
  BACKUP_DIR.mkdir(parents=True, exist_ok=True)
  stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
  backup_zip_path = BACKUP_DIR / f'backup-{stamp}.zip'
  print(f'Creating backup: {backup_zip_path}')

  exclude_roots = set(PROTECT_PATHS + ['backups'])  # also skip previous backups

  def should_exclude(rel: str) -> bool:
    rel = rel.replace('\\', '/')
    for p in exclude_roots:
      if rel == p or rel.startswith(p + '/'):
        return True
    return False

  files_added = 0
  with zipfile.ZipFile(backup_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(ROOT):
      rel_root = os.path.relpath(root, ROOT)
      rel_root_norm = '.' if rel_root == '.' else rel_root.replace('\\', '/')
      # Prune excluded directories early to avoid traversal cost
      pruned = []
      for d in list(dirs):
        rel_dir = f'{rel_root_norm}/{d}' if rel_root_norm != '.' else d
        if should_exclude(rel_dir):
          dirs.remove(d)
          pruned.append(d)
      for f in files:
        rel_file = f'{rel_root_norm}/{f}' if rel_root_norm != '.' else f
        if should_exclude(rel_file):
          continue
        # Skip the archive we are currently writing if our walk sees it (edge case)
        if backup_zip_path.name == f and rel_root_norm == 'backups':
          continue
        abs_path = os.path.join(root, f)
        zf.write(abs_path, rel_file)
        files_added += 1
        if files_added % 250 == 0:
          print(f'  Added {files_added} files...')
  print(f'Backup complete. {files_added} file(s) archived.')
  return str(backup_zip_path)


def prompt_yes_no(msg: str, default='n') -> bool:
  val = input(f"{msg} [{'Y/n' if default.lower()=='y' else 'y/N'}]: ").strip().lower() or default.lower()
  return val.startswith('y')


def protect_files_after_pull():
  """Re-assert protected files from backup or skip overwrite by using git checkout strategies.
  Because we want to avoid overwriting DBs and env/configs, we can reset those paths to their pre-pull state
  if the merge changed them.
  """
  changed = run(['git', '-C', str(ROOT), 'diff', '--name-only', 'HEAD@{1}', 'HEAD']).stdout.splitlines()
  protect = []
  for rel in changed:
    rel_norm = rel.replace('\\', '/')
    for p in PROTECT_PATHS:
      if rel_norm == p or rel_norm.startswith(p + '/'):
        protect.append(rel)
        break
  if protect:
    print('Reverting changes to protected paths to avoid overwrite:')
    for p in protect:
      print(f'  - {p}')
    # Restore previous version of protected files from the previous HEAD (HEAD@{1})
    for p in protect:
      try:
        run(['git', '-C', str(ROOT), 'checkout', 'HEAD@{1}', '--', p], check=True)
      except subprocess.CalledProcessError:
        # If path is new in repo, skip
        pass


def main():
  ensure_git_repo()
  branch = get_branch()
  fetch_remote()
  ahead, behind = ahead_behind(branch)
  if behind == 0 and ahead == 0:
    print('Up to date with remote. No changes available.')
    return
  if behind == 0 and ahead > 0:
    print(f'Local branch is ahead of origin/{branch} by {ahead} commit(s).')
    print('You may want to push your local changes before updating elsewhere.')
  if behind > 0:
    print(f'Remote has {behind} new commit(s) on origin/{branch}.')
    if not prompt_yes_no('Pull and update to the latest version?', default='n'):
      print('Update canceled.')
      return
    backup_path = make_backup()
    print(f'Backup saved to: {backup_path}')
    try:
      # Save current HEAD in reflog to allow restore of protected files
      run(['git', '-C', str(ROOT), 'pull', '--rebase', 'origin', branch], check=True)
      print('Pull complete.')
      protect_files_after_pull()
      print('Protected files re-asserted (DBs/env/config preserved).')
    except subprocess.CalledProcessError as e:
      print(f'Pull failed: {e}. You can restore from backup zip if needed.')
      sys.exit(1)

  print('Update process finished.')


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print('\nAborted by user.')
    sys.exit(1)