from kivy.app import App
from kivy.uix.label import Label
from kivy.core.window import Window

class SimpleTestApp(App):
    def build(self):
        Window.clearcolor = (0.5, 0.5, 0.8, 1)
        return Label(text="Test Background")

if __name__ == '__main__':
    SimpleTestApp().run()
