ThisBuild / organization  := "dev.hshn"
ThisBuild / homepage      := Some(url("https://github.com/hshn/crypto4s"))
ThisBuild / licenses      := Seq(License.MIT)
ThisBuild / versionScheme := Some("early-semver")
ThisBuild / developers    := List(Developer("hshn", "Shota Hoshino", "sht.hshn@gmail.com", url("https://github.com/hshn")))
ThisBuild / scalaVersion  := "3.7.0"

lazy val root = (project in file(".") withId "crypto4s")
  .settings(
    publish / skip := true
  )
  .aggregate(
    core,
    bouncycastle
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

lazy val bouncycastle = (project in file("projects/bouncycastle") withId "crypto4s-bouncycastle")
  .dependsOn(core % "test->test;compile->compile")
  .settings(
    libraryDependencies ++= Seq(
      Libs.bouncycastle.bcpix
    )
  )

ThisBuild / sonatypeCredentialHost := xerial.sbt.Sonatype.sonatypeCentralHost
