# Screenshots

The pictures the top-level README shows. They are taken by hand on a real
Windows 11 PC running a released build, never mocked up.

| File | What to capture |
|---|---|
| `dashboard-overview.png` | The dashboard's Overview tab with every module running. |
| `dashboard-alerts.png` | The Alerts tab with a few alerts, one selected so **Help with this alert** shows. |
| `dashboard-checkup.png` | The Checkup tab after a check. |
| `critical-alert.png` | The critical alert window. Tripping a canary file in a test folder is a harmless way to raise one. |
| `tray-menu.png` | The tray icon with its menu open. |

Guidelines:

- PNG, at 100% display scaling, cropped to the window. About 1,200 pixels
  wide is plenty.
- Use the light theme so the pictures match each other.
- Check each picture for anything personal before committing it: user
  names in paths, the PC's name, browser profile names, extension lists.
  A test account or a fresh virtual machine avoids most of that.
- When a window changes noticeably in a release, retake its picture.

Once the files are here, uncomment the Screenshots block near the top of
the [README](../../README.md).
