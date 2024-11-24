import org.typelevel.sbt.tpolecat.TpolecatPlugin
import org.typelevel.sbt.tpolecat.TpolecatPlugin.autoImport.*
import org.typelevel.scalacoptions.ScalacOptions
import sbt.*
import sbt.plugins.JvmPlugin

object GlobalPlugin extends AutoPlugin {
  override def trigger = allRequirements

  override def requires = JvmPlugin && TpolecatPlugin

  override def projectSettings: Seq[Def.Setting[_]] = Seq(
    tpolecatExcludeOptions ++= ScalacOptions.warnUnusedOptions + ScalacOptions.privateKindProjector,
    Test / tpolecatExcludeOptions ++= Set(
      ScalacOptions.warnNonUnitStatement
    ),
    tpolecatScalacOptions ++= Set(
      // ScalacOptions.explain,
      ScalacOptions.other("-explain-cyclic")
    )
  )
}
