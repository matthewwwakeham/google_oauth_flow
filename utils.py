import random

def get_random_color():
    def is_gray_or_black_or_white(r, g, b):
        is_gray = abs(r - g) < 40 and abs(g - b) < 40 and abs(r - b) < 40
        is_black_or_white = (r < 40 and g < 40 and b < 40) or (r > 215 and g > 215 and b > 215)
        return is_gray or is_black_or_white

    def is_too_bright(r, g, b):
        luminance = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255
        return luminance > 0.5

    while True:
        r, g, b = [random.randint(0, 255) for _ in range(3)]
        if not is_gray_or_black_or_white(r, g, b) and not is_too_bright(r, g, b):
            return f'#{r:02X}{g:02X}{b:02X}'