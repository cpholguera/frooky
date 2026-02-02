Java.perform(function () {
  console.log("frida attached and Java is ready")
  setTimeout(function () {
    console.log("done")
  }, 1500)
})
