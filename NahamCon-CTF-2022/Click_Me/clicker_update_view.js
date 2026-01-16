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
