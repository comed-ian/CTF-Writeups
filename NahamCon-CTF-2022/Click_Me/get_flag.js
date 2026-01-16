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
