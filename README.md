# IngetID example

Java example application for the BankID simulator [IngetID](https://blankid.fly.dev/). Java 17 was used for development and testing and [Main.java](./src/main/java/dev/inget/id/Main.java) contains everything interesting.

To try out the local IngetID version, before running the example application start the server: `blankid` or `blankid.exe`.

To download dependencies (Jackson) and start the example application through Maven:

```
mvn compile exec:java
```

From there you can choose to use the BankID official test environment, [IngetID remote](https://ingetid.fly.dev/admin), or
[IngetID local](http://127.0.0.1:6080/admin).

(If you started the application from within the dev container ports may be different on the host. See the "PORTS" tab in VS Code.)