Java.perform(function () {
  console.log("frida attached and Java is ready")
  setTimeout(function () {
    console.log("detaching frida")
    Java.perform(function () {
      Java.use("java.lang.System").exit(0)
    })
  }, 1500)
})