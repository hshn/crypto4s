ThisBuild / organization  := "dev.hshn"
ThisBuild / homepage      := Some(url("https://github.com/hshn/crypto4s"))
ThisBuild / licenses      := Seq(License.MIT)
ThisBuild / versionScheme := Some("early-semver")
ThisBuild / developers    := List(Developer("hshn", "Shota Hoshino", "sht.hshn@gmail.com", url("https://github.com/hshn")))
ThisBuild / scalaVersion  := "3.5.2"

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
