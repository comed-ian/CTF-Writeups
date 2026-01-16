# Click Me

## Setup

The easiest way to get up and running is installing a virtual device from Android
Studio. This solution uses the Pixel 8 (API 34) rooted using
[this guide](https://advaitsaravade.me/rooting-an-android-emulator-in-2025/). The
emulator, once installed and rooted, is booted with the following command:

```bash
emulator -avd Pixel_8 -writable-system -no-snapshot-load 
```

Install the challenge APK by dragging and dropping, and download
[`frida-server`](https://github.com/frida/frida/releases) with the appropriate
architecture for the emulator (in this case, Android-ARM64). Push the file to the device
with `adb push frida-server<version> /data/local/tmp/`.

Install Frida on the host machine. It is useful to match the `frida` Python package
to the target `frida-server` version, in this case v16.6.1.

```bash
pip3 install frida-tools
pip3 install frida==16.6.1
```

## Investigation

## Running the App

The app appears very simple: it shows a cookie in the middle of the screen
and contains a button that requests the flag. Clicking the cookie increments
a counter, and selecting the flag displays an error that we do not have enough
cookies:

![not enough cookies]('./_images/img1.png')

Initial investigation suggests that we need to click the cookie a certain number
of times and then request the flag.

## Static Reverse Engineering

Opening `click_me.apk` in JEB and navigating to `AndroidManifest.xml` shows
that the application is rather lean, with a single `activity` definition for
the app's entry point (`android.intent.category.LAUNCHER`):
`com.example.clickme.MainActivity`.

```xml
<manifest>
  <!-- ... -->
  <application
    android:allowBackup="true"
    android:appComponentFactory="androidx.core.app.CoreComponentFactory"
    android:extractNativeLibs="false"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/app_name"
    android:roundIcon="@mipmap/ic_launcher_round"
    android:supportsRtl="true"
    android:theme="@style/Theme.ClickMe">
    <activity
      android:exported="true"
      android:name="com.example.clickme.MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <provider
      android:authorities="com.example.clickme.androidx-startup"
      android:exported="false"
      android:name="androidx.startup.InitializationProvider">
      <meta-data
        android:name="androidx.emoji2.text.EmojiCompatInitializer"
        android:value="androidx.startup"/>
      <meta-data
        android:name="androidx.lifecycle.ProcessLifecycleInitializer"
        android:value="androidx.startup"/>
    </provider>
  </application>
</manifest>
```

This class is relatively sparse as well, containing a static constructor and
methods `cookieViewClick`, `getFlag`, `getFlagButtonClick`, and `onCreate`.
The `onCreate` method is responsible for rendering the activity and does not
contain anything particularly interesting. The `getFlag` is a native method,
meaning it is called from a compiled shared object. Native libraries are
loaded through a call to `System.loadLibrary`, `Runtime.loadLibrary`, or
a third-party package like Facebook's [SoLoader](https://github.com/facebook/SoLoader).
The constructor has a call to load the native `clickme` library:

```java
static {
    MainActivity.Companion = new Companion(null);
    System.loadLibrary("clickme");
}
```

This means we should expect a file `libclickme.so` in the extracted APK.
Extracting the file with `apktool d <filename>` and searching in the extracted
`libs/` directory confirms this assumption.

```
$ apktool d click_me.apk 
I: Using Apktool 2.11.1 on click_me.apk with 8 threads
I: Baksmaling classes.dex...
I: Loading resource table...
I: Decoding file-resources...
I: Loading resource table from file: /Users/iand/Library/apktool/framework/1.apk
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
I: Regular manifest package...
I: Copying original files...
I: Copying lib...
I: Copying unknown files...

$ ls click_me/lib/arm64-v8a 
libclickme.so
```

Turning attention back to the APK shows an interesting conundrum-the app
calls the native `getFlag()` function when the number of clicks equals 99999999,
however the incrementer does not let the click count pass 13371337:

```java
    public final void cookieViewClick(View view0) {
        int v = this.CLICKS + 1;
        this.CLICKS = v;
        if(v >= 13371337) {
            this.CLICKS = 13371337;
        }

        ((TextView)this.findViewById(0x7F080075)).setText(String.valueOf(this.CLICKS));  // id:cookieCount
    }

    public final void getFlagButtonClick(View view0) {
        Intrinsics.checkNotNullParameter(view0, "view");
        if(this.CLICKS == 99999999) {
            String s = this.getFlag();
            Toast.makeText(this.getApplicationContext(), s, 0).show();
            return;
        }

        Toast.makeText(this.getApplicationContext(), "You do not have enough cookies to get the flag",
                 0).show();
    }
```

One option to find the flag is to reverse engineer `getFlag()` in the shared object.
Native functions (excluding those registered by a call to `registerNatives`) can
be easily identified as they start with `Java_` and contain the package, class and method
name in their title: in this case, `Java_com_example_clickme_MainActivity_getFlag`.
A quick investigation shows calls to `operator new` and `operator delete`, indicating
this is compiled C++. The logic is rather gross-there are multiple `while(1)` loops
that seem to iterate over one or more byte buffers and follow branching logic based
on state changes. Statically reversing the flag does not seem like the best use of
time and energy.

## Dynamic Reverse Engineering

An alternative to static reverse engineering is using dynamic tooling like Frida
to manually manipulate memory within the process. This is particularly useful for
the current challenge, as only one parameter requires modification (the `MainActivity`'s
`CLICK` field). There are a couple ways to solve this app.

### Manipulating Instance Parameters

One way of solving the challenge is to manually manipulate the value of
`MainActivity.CLICKS` to be the desired value and continuing execution.
This allows the user to click the "GET FLAG" button with the click value
set as required.

The steps for the script are:
1. Attach to an existing `Click Me` process
1. Find the `MainActivity` instance
1. Find the `CLICK` parameter and set its value to 99999999
1. Continue execution

The following script (`clicker.js`) performs these operations:

```javascript
Java.deoptimizeEverything();

Java.perform(() => {
    // Java.choose to find the instance of the class on the Java heap
    Java.choose('com.example.clickme.MainActivity', {
        // Once found, perform the following operations with the instance
        onMatch: function (instance) {
            instance.CLICKS.value = 99999999; // set value of CLICKS and continue
        },
        // Once finished searching, perform the following actions
        onComplete: function () {}
    });
});
```

This script finds the active `MainActivity` instance on the Java heap
and sets its parameter to the desired value. It is worth noting that this
method does not call `MainActivity.cookieViewClick` to update the view-
doing so would trigger the logic check and set the cookie back to 13371337:

```java
if(v >= 13371337) {
    this.CLICKS = 13371337;
}
```

That said, the `CLICKS` value is changed, just not displayed.

Running the script with the following command attaches to the existing
`Click Me` process and execute the Javascript:

```bash
frida -D emulator-5554 -l clicker.js 'Click Me'
```

> `emulator-5554` is the Frida device ID, which can be found by running `frida-ls-devices`

Now, clicking the "GET FLAG" button confirms the change and prints the deobfuscated flag!

![Flag1](clicker1.png)

### Updating Views

As mentioned, the prior solution does not update the view. However, what if
this behavior is desired? The following decompiled Java code executes the view
update in `MainActivity.cookieViewClick`:

```java
((TextView)this.findViewById(0x7F080075)).setText(String.valueOf(this.CLICKS));
```

Directly replicating this in Frida will not work-the script will throw an error
stating `CalledFromWrongThreadException: Only the original thread that created a
view hierarchy can touch its views.` This means that the main UI thread must
be the one performing the update, and apparently the thread executing Frida code
is not that thread. This boils down to a protection by
[`FLAG_SECURE`](https://developer.android.com/security/fraud-prevention/activities#flag_secure),
which is meant to protect against displaying "non-secure" views (like screen casting).
In this case, it means the Frida script must update the Activity's `Window` to disable
this protection. Hamza Boulanouar has a
[nice write-up](https://www.securify.nl/en/blog/android-frida-hooking-disabling-flagsecure/)
on this technique, from which the following code was adapted:

```javascript
// clicker_update_view.js
Java.deoptimizeEverything();

Java.perform(() => {
   // https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
   var FLAG_SECURE = 0x2000;
   var Runnable = Java.use("java.lang.Runnable");
   // Adapted from https://www.securify.nl/en/blog/android-frida-hooking-disabling-flagsecure/
   var DisableSecureRunnable = Java.registerClass({
      name: "com.tmp.DisableSecureRunnable",
      implements: [Runnable],
      fields: {
          activity: "android.app.Activity",
      },
      methods: {
         $init: [{
            returnType: "void",
            argumentTypes: ["android.app.Activity"],
            implementation: function (activity) {
               this.activity.value = activity;
            }
         }],
         run: function() {
            var flags = this.activity.value.getWindow().getAttributes().flags.value; // get current value
            flags &= ~FLAG_SECURE; // toggle it
            this.activity.value.getWindow().setFlags(flags, FLAG_SECURE); // disable it!
            console.log("Done disabling SECURE flag...");
         }
      }
   });
   // Java.choose to find the instance of the class on the Java heap
   Java.choose('com.example.clickme.MainActivity', {
      // Once found, perform the following operations with the instance
      onMatch: function (instance) {
          instance.CLICKS.value = 99999999; // set value of CLICKS and continue
          var textView = Java.use("android.widget.TextView");
          // Create runnable to disable UI protections
          var runnable = DisableSecureRunnable.$new(instance);
          instance.runOnUiThread(runnable);
          // Use logic in MainActivity.cookieViewClick to update the UI
          console.log('Updating UI')
          var str = Java.use("java.lang.String")
          Java.cast(instance.findViewById(0x7F080075), textView)
             .setText(str.$new(instance.CLICKS.value.toString()));
      },
      // Once finished searching, perform the following actions
      onComplete: function () {}
   });
});
```

Running this script with the following command not only updates the `CLICKS`
value, but also renders the new UI View!

```bash
frida -D emulator-5554 -l clicker.js 'Click Me'
```

![clicker2](clicker2.png)

### Executing Shared Library Code Directly

Another option for solving this challenge is to avoid touching the `CLICKS`
field entirely and jump right to the winning condition code,
`String s = this.getFlag();`. This calls the native method registered to
the `MainActivity` instance, which is available via the prior `clicker.js`
Frida script. Executing that method directly returns a `java.lang.String`,
which Frida can directly log to the console:

```javascript
// get_flag.js
Java.deoptimizeEverything();

Java.perform(() => {
    // Java.choose to find the instance of the class on the Java heap
    Java.choose('com.example.clickme.MainActivity', {
        // Once found, perform the following operations with the instance
        onMatch: function (instance) {
            var flag = instance.getFlag();
            console.log(flag);
        },
        // Once finished searching, perform the following actions
        onComplete: function () {}
    });
});  
```

Running the script bypasses all the other Java checks and simply
logs the flag to the executing terminal!

```
$ frida -D emulator-5554 -l get_flag.js 'Click Me'
     ____
    / _  |   Frida 16.6.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Attaching...                                                            
flag{849d9e5421c59358ee4d568adebc5a70}
[Android Emulator 5554::Click Me ]->
```
