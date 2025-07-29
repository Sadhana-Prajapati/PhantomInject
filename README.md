## Phantominject

Inject your custom DLL into `victim_app.py` using the provided `injector.py`.

Update the `TARGET_PROCESS` in `injector.py` to match the actual process name (`victim_app.py` as `.exe`).

Run both files. When the injector finds the process and injects the DLL, it will display the PID and a success message.

No flag file. The terminal output is your proof of success.
