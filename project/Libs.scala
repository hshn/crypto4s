import sbt._

object Libs {
  object zio {
    private val version = "2.1.13"

    val test         = "dev.zio" %% "zio-test"          % version
    val testSbt      = "dev.zio" %% "zio-test-sbt"      % version
    val testMagnolia = "dev.zio" %% "zio-test-magnolia" % version
  }

  object bouncycastle {
    val bcpix = "org.bouncycastle" % "bcpkix-jdk18on" % "1.79"
  }
}
