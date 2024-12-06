ThisBuild / scalaVersion := "3.5.2"

lazy val root = (project in file(".") withId "crypto4s")
  .aggregate(
    core
  )

lazy val core = (project in file("projects/core") withId "crypto4s-core")
  .settings(
    libraryDependencies ++= Seq(
      Libs.bouncycastle.bcpix,
      Libs.zio.test         % Test,
      Libs.zio.testSbt      % Test,
      Libs.zio.testMagnolia % Test
    )
  )
