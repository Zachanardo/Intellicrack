
import psutil
import frida
import time
import os

FRIDA_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "adobe_bypass.js")

ADOBE_PROCESSES = [
    "Photoshop.exe",
    "Illustrator.exe",
    "PremierePro.exe",
    "AfterFX.exe",
    "MediaEncoder.exe",
    "InDesign.exe",
    "Animate.exe",
    "Audition.exe",
    "CharacterAnimator.exe",
    "Dreamweaver.exe",
    "Lightroom.exe",
    "LightroomClassic.exe",
    "Substance 3D Designer.exe",
    "Substance 3D Painter.exe",
    "Substance 3D Sampler.exe",
    "Substance 3D Stager.exe",
    "Substance 3D Modeler.exe"
]

injected = set()

def inject(target_name):
    try:
        session = frida.attach(target_name)
        with open(FRIDA_SCRIPT_PATH, "r", encoding="utf-8") as f:
            script = session.create_script(f.read())
            script.load()
        injected.add(target_name)
    except Exception as e:
        pass  # Silent fail to remain stealthy

def get_running_adobe_apps():
    running = []
    for proc in psutil.process_iter(attrs=['name']):
        try:
            pname = proc.info['name']
            if pname in ADOBE_PROCESSES and pname not in injected:
                running.append(pname)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return running

def monitor_loop():
    while True:
        active = get_running_adobe_apps()
        for proc in active:
            inject(proc)
        time.sleep(2)

if __name__ == "__main__":
    monitor_loop()
