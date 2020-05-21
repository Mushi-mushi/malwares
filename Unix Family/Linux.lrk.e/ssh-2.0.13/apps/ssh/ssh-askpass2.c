/*

ssh-askpass.c

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

#include "sshincludes.h"
#include "sshgetopt.h"

#ifdef time
#undef time
#endif 

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xresource.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/cursorfont.h>
#include "sshmalloc.h"

#define SSH_DEBUG_MODULE "SshAskPass"

#ifdef HAVE_LIBWRAP
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* HAVE_LIBWRAP */

#define DISPLAY_VARIABLE "DISPLAY"
#define RESOURCES_MAX_LENGTH 20000L
#define CANCEL_STRING "Cancel"

/* 'none' must be the last one in this enum, starting from zero */

typedef enum { background, hilight, shadow, text,
               dark_led, light_led, none } color_type;

/* X data structures */

Display *display;
Window main_window, cancel_button;
XrmDatabase database;
XModifierKeymap *modifiers;
XFontStruct *font_struct;
Colormap map;
Font font;

/* Default values for some resources */

char *font_spec = "-*-times-bold-r-*-*-*-140-*-*-*-*-iso8859-1";
char *font_fall_back = "-*-*-*-r-*-*-*-*-*-*-*-*-iso8859-1";
char *background_color_name = "gray80";
char *foreground_color_name = "black";
char *prompt = "Please enter your authentication passphrase:";

/* Color tables */

long color[none];
GC gc[none];

/* Geometry */

int w_width, w_height, w_x, w_y;
int led_width = 20;
int led_height = 10;
int led_i_height = 8;
int led_i_width = 18;
int relief = 4;
int margin = 4;
int leds;
int b_width, b_height;

/* User interfacing */

char phrase[256];
char *ppointer = phrase;
int cancel_pressed = 0;
int exiting = 0;
int next_led = 0;
int leds_x, leds_y;
int *led_state;

/* Timeout */
unsigned int timeout_time;

void fatal(char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(1);
}

/* Open connection to the X display. */

void open_display()
{
  char *display_name;

  display_name = getenv(DISPLAY_VARIABLE);
  if (!display_name)
    fatal("Display not set, cannot open display.");

  display = XOpenDisplay(display_name);

  if (!display)
    fatal("Cannot open display \"%s\".\n", display_name);
}

/* Close the display after freeing data structures. */

void close_display()
{
  XFreeModifiermap(modifiers);
  XUnloadFont(display, font);
  ssh_xfree(led_state);
  XCloseDisplay(display);
}

/* Create the graphics contexts. Color version. */

void create_GCs()
{
  int i;
  XGCValues values;
  values.function = GXcopy;
  values.font = font;
  values.fill_style = FillSolid;
  values.background = color[0];
  for (i = 0; i < none; i++)
    {
      values.foreground = color[i];
      gc[i] = XCreateGC(display, main_window, GCForeground | GCBackground |
                        GCFillStyle | GCFunction | GCFont,
                        &values);
    }
}

/* Create the graphics contexts. B/W version. */

void create_GCs_bw()
{
  int i;
  XGCValues values;
  values.function = GXcopy;
  values.font = font;
  values.fill_style = FillSolid;
  values.background = WhitePixel(display, DefaultScreen(display));
  for (i = 0; i < none; i++)
    {
      values.foreground = ((i == text || i == shadow || i == dark_led)
                           ? BlackPixel(display, DefaultScreen(display))
                           : WhitePixel(display, DefaultScreen(display)));
      gc[i] = XCreateGC(display, main_window, GCForeground | GCBackground |
                        GCFillStyle | GCFunction | GCFont,
                        &values);
    }
}

/* Try to allocate the colors we would like to use.
   If any of the allocations fails, revert to black'n'white mode. */

void allocate_colors()
{
  XColor xcolor, exact_color;
  int red, green, blue;

  map = DefaultColormap(display, DefaultScreen(display));
  if(!XAllocNamedColor(display, map, background_color_name,
                       &xcolor, &exact_color))
    goto revert;

  color[background] = xcolor.pixel;
  exact_color.flags = DoRed | DoGreen | DoBlue;
  red = exact_color.red;
  blue = exact_color.blue;
  green = exact_color.green;
  
  red += 16384;
  if (red > 65535) red = 65535;
  blue += 16384;
  if (blue > 65535) blue = 65535;
  green += 16384;
  if (green > 65535) green = 65535;
  
  exact_color.red = red;
  exact_color.blue = blue;
  exact_color.green = green;
  
  if(!XAllocColor(display, map, &exact_color))
    goto revert;

  color[hilight] = exact_color.pixel;
  
  red -= 32768;
  if (red < 0) red = 0;
  blue -= 32768;
  if (blue < 0) blue = 0;
  green -= 32768;
  if (green < 0) green = 0;
  
  exact_color.red = red;
  exact_color.blue = blue;
  exact_color.green = green;
  
  if (!XAllocColor(display, map, &exact_color))
    goto revert;

  color[shadow] = exact_color.pixel;
  
  if (!XAllocNamedColor(display, map, foreground_color_name,
                   &xcolor, &exact_color))
    goto revert;

  color[text] = xcolor.pixel;

  exact_color.red = 0x9000;
  exact_color.green = 0xd000;
  exact_color.blue = 0x9000;
  if(!XAllocColor(display, map, &exact_color))
    goto revert;

  color[light_led] = exact_color.pixel;

  exact_color.red = 0x0;
  exact_color.green = 0x0;
  exact_color.blue = 0x8000;
  if(!XAllocColor(display, map, &exact_color))
    goto revert;

  color[dark_led] = exact_color.pixel;
  XSetWindowColormap(display, main_window, map);
  create_GCs();
  return;

revert:
  /* switch to black'n'white mode */
  create_GCs_bw();
}

/* Calculate dimensions of a button containing 'string' inside it. */

void button_dimensions(char *string, int *width, int *height)
{
  XCharStruct overall;
  int dir, asc, desc;
  XTextExtents(font_struct, string, strlen(string),
               &dir, &asc, &desc, &overall);
  *width = overall.width + 4 + 2 * margin;
  *height = overall.ascent + overall.descent + 1 + 4 + 2*margin;
}

/* Open windows (the dialog box and the cancel button). */

void open_windows()
{
  int i; int scrap;
  XSetWindowAttributes attributes;
  XSizeHints *hints = XAllocSizeHints();

  attributes.backing_store = WhenMapped;
  attributes.cursor = XCreateFontCursor(display, XC_X_cursor);

  main_window = XCreateWindow(display, DefaultRootWindow(display),
                              w_x, w_y, w_width, w_height, 0,
                              CopyFromParent, InputOutput,
                              CopyFromParent, CWCursor | CWBackingStore,
                              &attributes);

  hints->flags = PPosition | PSize | PMinSize | PMaxSize | PWinGravity;
  hints->x = w_x; hints->y = w_y;
  hints->width = w_width; hints->height = w_height;
  hints->min_width = hints->max_width = w_width;
  hints->min_height = hints->max_height = w_height;
  hints->win_gravity = CenterGravity;
  XSetWMNormalHints(display, main_window, hints);

  XStoreName(display, main_window, "SSH Authentication Passphrase Request");

  /* This is a dialog box, I think. */
  XSetTransientForHint(display, main_window,
                       DefaultRootWindow(display));
  XFree(hints);

  cancel_button = XCreateWindow(display, main_window,
                                w_width - relief - margin - b_width,
                                w_height - relief - margin - b_height,
                                b_width, b_height,
                                0,
                                CopyFromParent, InputOutput,
                                CopyFromParent, CWCursor |
                                CWBackingStore,
                                &attributes);
  
  leds = (w_width - relief * 2 - margin * 2 + (led_width - led_i_width)) /
    led_width;
  scrap = (w_width - relief * 2 - margin * 2 + (led_width - led_i_width)) %
    led_width;
  leds_x = relief + margin + scrap/2;

  led_state = ssh_xmalloc(sizeof(int) * leds);
  for (i = 0; i < leds; i++) led_state[i] = 0;
  
  attributes.cursor = XCreateFontCursor(display, XC_top_left_arrow);
  XChangeWindowAttributes(display, cancel_button, CWCursor | CWBackingStore,
                          &attributes);
}

/* Map the windows. */

void map_windows()
{
  XMapRaised(display, main_window);
  XMapWindow(display, cancel_button);
}

/* Load the font wanted. */

void get_font()
{
  font_struct = XLoadQueryFont(display, font_spec);
  if (!font_struct)
    {
      font_struct = XLoadQueryFont(display, font_fall_back);
      if (!font_struct)
        fatal ("Cannot load any font.");
    }
  font = font_struct->fid;
}

/* Calculate correct geometry for the main window. */

void compute_dimensions()
{
  Status status;
  Window root;
  int dummy, d_width, d_height;
  int dir, asc, desc;
  XCharStruct overall;

  XTextExtents(font_struct, prompt, strlen(prompt),
               &dir, &asc, &desc, &overall);

  button_dimensions(CANCEL_STRING, &b_width, &b_height);

  w_width = XTextWidth(font_struct, prompt, strlen(prompt));
  if (b_width > w_width) w_width = b_width;
  w_width += relief * 2 + margin * 2;

  w_height = asc + desc - 1 + margin * 2 + b_height + led_height;

  w_height += relief * 2 + margin * 2;
  status = XGetGeometry(display, DefaultRootWindow(display),
                        &root, &dummy, &dummy, (unsigned int *)&d_width,
                        (unsigned int *)&d_height, (unsigned int *)&dummy, 
                        (unsigned int *)&dummy);
  w_x = (d_width - w_width) / 2;
  w_y = (d_height - w_height) / 2;
}

/* An auxiliary function for getting a resource from the xrm. */

void get_resource(char *name, char *class, char **where)
{
  char *type;
  XrmValue value;
  if (XrmGetResource(database, name, class, &type, &value) == True)
    *where = value.addr;
}

/* Read and get some resources. */

void read_resources()
{
  Status err;
  unsigned char *prop_return;
  unsigned long nitems_return, bytes_return;
  int format_return;
  Atom atom_return;

  /* Read the current database in. */
  database = NULL;
  XrmInitialize();

  err = XGetWindowProperty(display,
                           DefaultRootWindow(display),
                           XA_RESOURCE_MANAGER,
                           0L, RESOURCES_MAX_LENGTH,
                           False,
                           XA_STRING,
                           &atom_return,
                           &format_return,
                           &nitems_return,
                           &bytes_return,
                           &prop_return);

  if (err == Success)
    {
      if (prop_return != NULL)
        {
          database = XrmGetStringDatabase(prop_return);
          XFree(prop_return);
        }
    }
  else
    {
      fatal("XGetWindowProperty failed.");
    }

  if (!database) return;

  get_resource("ssh.askpass.font", "SSH.AskPass.Font", &font_spec);
  get_resource("ssh.askpass.background","SSH.AskPass.Background",
               &background_color_name);
  get_resource("ssh.askpass.foreground","SSH.AskPass.Foreground",
               &foreground_color_name);
  get_resource("ssh.askpass.prompt","SSH.AskPass.Prompt",
               &prompt);
}

/* A function to print a string. Return the y-coordinate of the bottom
   of the string's bounding box. */

int put_string(int x, int y, char *string, int color, Window window)
{
  XCharStruct overall;
  int dir, asc, desc;
  XTextExtents(font_struct, string, strlen(string),
               &dir, &asc, &desc, &overall);
  y += overall.ascent;
  XDrawString(display, window, gc[color],
              x, y, string, strlen(string));
  return (y + overall.descent);
}

/* Draw a raised/sunken box. */

void relief_box(int x, int y, int a, int b, int left, int right, int depth,
                int fill, Window window)
{
  int i;
  for (i = 0; i < depth; i++)
    {
      XDrawLine(display, window, gc[left],
                i + x, i + y, i + x, b - i);
      XDrawLine(display, window, gc[left],
                i + x, i + y, a - i, i + y);
      XDrawLine(display, window, gc[right],
                a - i, b - i,
                i + x, b - i);
      XDrawLine(display, window, gc[right],
                a - i, b - i,
                a - i, i + y);
    }
  if (fill != none)
    XFillRectangle(display, window,
                   gc[fill], i + x, i + y, a - x - 2*i + 1, b - y - 2*i + 1);
}

/* Draw a specific led. */

void draw_led(int no, int on)
{
  relief_box(leds_x + led_width * no, leds_y,
             leds_x + led_width * no + led_i_width,
             leds_y + led_height, shadow, hilight, 2, 
             on ? light_led : dark_led, main_window);
}

/* Draw a button with certain string inside. */

void draw_button(char *string, Window window, int width, int height,
                 int pushed)
{
  if (!pushed)
    {
      relief_box(0, 0, width - 1, height - 1, hilight, shadow,
                 2, background, window);
      put_string(1 + margin, 1 + margin, string, text, window);
    }
  else
    {
      relief_box(2, 2, width - 1, height - 1, shadow, hilight,
                 2, background, window);
      relief_box(0, 0, width - 1, height - 1, shadow, hilight,
                 2, none, window);
      put_string(3 + margin, 3 + margin, string, text, window);
    }
}

/* Draw the dialog box and the cancel button. */

void draw_it()
{
  int y; int i;
  relief_box(0, 0, w_width - 1, w_height - 1, hilight, shadow, relief,
             background, main_window);
  y = put_string(relief + margin, relief + margin, prompt, text, main_window);

  leds_y = y + margin;

  for (i = 0; i < leds; i ++)
    {
      draw_led(i, led_state[i]);
    }
  draw_button(CANCEL_STRING, cancel_button, b_width, b_height, 0);
}

/* Handle different X events. */

void button_press(XButtonEvent *event)
{
  if (event->subwindow != cancel_button)
    return;
  draw_button(CANCEL_STRING, cancel_button, b_width, b_height, 1);
  cancel_pressed = 1;
}

void button_release(XButtonEvent *event)
{
  if (event->subwindow != cancel_button)
    {
      if (cancel_pressed)
        {
          draw_button(CANCEL_STRING, cancel_button, b_width, b_height, 0);
          cancel_pressed = 0;
        }
    }
  else
    {
      if (cancel_pressed)
        exiting = 2;
    }
}

void advance_leds()
{
  led_state[next_led] ^= 1;
  draw_led(next_led, led_state[next_led]);
  next_led = (next_led + 1) % leds;
}

void backward_leds()
{
  next_led--; if (next_led == -1) next_led += leds;
  led_state[next_led] ^= 1;
  draw_led(next_led, led_state[next_led]);  
}

/* Handle key press. */
void key_press(XKeyEvent *event)
{
  char buf[100];
  char *ptr = buf;
  int in_buf;

  KeySym sym;

  in_buf = XLookupString(event, buf, 100, &sym, NULL);

  if ((sym != NoSymbol) && (sym & (0xff)) == sym)
    {
      while(in_buf-- > 0)
        {
          if ((ppointer - phrase) < 255)
            {
              *ppointer++ = *ptr++;
              advance_leds();
            }
        }
    }
  else
    /* Some special symbol. */
    {
      switch(sym)
        {
          /* These cause the last character to be eaten. */
        case XK_Delete:
        case XK_BackSpace:
          if (ppointer != phrase)
            {
              ppointer--;
              backward_leds();        
            }
          break;
          /* These cause the event loop to terminate. */
        case XK_Return:
        case XK_Linefeed:
        case XK_KP_Enter:
          exiting = 1;
          return;
        case XK_Escape:
        case XK_Cancel:
          exiting = 2;
          return;
        }
    }
}

/* Read the modifiers mapping. */
void check_keyboard()
{
  modifiers = XGetModifierMapping(display);
}

void timeout(int sig) /*ARGUSED*/
{
  close_display();
  exit(0);
}

/* Event loop. */
void event_loop()
{
  int focused = 0;
  XEvent event;
  XSelectInput(display, main_window, ButtonPressMask |
               VisibilityChangeMask | StructureNotifyMask |            
               ExposureMask | ButtonReleaseMask | KeyPressMask);

  /* Windows must be mapped not before XSelectInput, so that the
     mapping notify will certainly arrive to our event loop. */
  map_windows();

  if (timeout_time > 0)
    {
      signal(SIGALRM, timeout);
      alarm(timeout_time);
    }
  while(exiting == 0)
    {
      XNextEvent(display, &event);
      switch (event.type)
        {
        case ButtonPress:
          button_press(&event.xbutton);
          break;
        case ButtonRelease:
          button_release(&event.xbutton);
          break;
        case KeyPress:
          key_press(&event.xkey);
          break;
        case Expose:
          if (event.xexpose.count == 0) {
            draw_it();
            if (!focused) {
              XSetInputFocus(display, main_window, RevertToPointerRoot,
                             CurrentTime);
              focused = 1;
            }
          }
          break;                     
        }
    }
  switch (exiting)
    {
    case 1:
      *ppointer = 0;
      printf("%s\n", phrase);
      break;     
    default:
      break;      
    }
}

int main(int argc, char **argv)
{
  int opt;

  open_display();
  read_resources();

  /* If we get just one argument, use it as the prompt. */
  /* This must be called not before than read_resources() if we
     wish to override the default from the resources database. */
  while ((opt = ssh_getopt(argc, argv, "t:", NULL)) != -1)
    {
      switch (opt)
        {
        case 't':
          timeout_time = (unsigned int)atoi(ssh_optarg);
          if (timeout_time < 0)
            timeout_time = 0;
          break;

        default:
          exit(1);
        }
    }
  if (argc > ssh_optind)
    prompt = argv[ssh_optind];
  get_font();
  compute_dimensions();
  open_windows();
  allocate_colors();
  check_keyboard();
  event_loop();
  close_display();

  return 0;
}
