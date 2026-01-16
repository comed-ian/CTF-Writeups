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
