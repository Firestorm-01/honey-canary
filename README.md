Honey-Canary — Story & System Description
The Idea
Imagine a security team protecting a company network.
Instead of guarding only real secrets, they also place fake bait:
fake credentials
fake API keys
fake confidential documents
fake database exports
Nobody legitimate should ever touch them.
So if somebody does…
that itself becomes the alarm.
Honey-Canary is the silent watcher assigned to those bait files.
What the Program Does
The application continuously monitors a chosen file using low-level operating system event systems:
Linux → inotify
Windows → ReadDirectoryChangesW
It watches for:
reads
writes
renames
deletions
permission changes
access attempts
The moment any suspicious interaction occurs:
The event is captured
Process details are collected
User information is extracted
Alerts are sent immediately
Evidence is preserved
