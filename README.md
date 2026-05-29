# Honey-Canary
⚠️Entire project needs to be tested before usage.This is a prototype. 
## The Idea

Imagine a security team protecting a company network. Instead of guarding only real secrets, they also place fake bait:

- Fake credentials
- Fake API keys
- Fake confidential documents
- Fake database exports

Nobody legitimate should ever touch them. So if somebody does… that itself becomes the alarm.

Honey-Canary is the silent watcher assigned to those bait files.

## What the Program Does

The application continuously monitors a chosen file using low-level operating system event systems:

**Supported Platforms:**
- Linux → inotify
- Windows → ReadDirectoryChangesW

**It watches for:**
- Reads
- Writes
- Renames
- Deletions
- Permission changes
- Access attempts

**The moment any suspicious interaction occurs:**

1. The event is captured
2. Process details are collected
3. User information is extracted
4. Alerts are sent immediately
5. Evidence is preserved
