name := "SignMessages"

version := "0.1"

scalaVersion := "2.12.6"

libraryDependencies ++= Seq("com.roundeights" %% "hasher" % "1.2.0"
  , "io.lemonlabs" %% "scala-uri" % "1.1.1"
  ,"org.scalaj" %% "scalaj-http" % "2.4.0"
  ,"org.scala-lang.modules" %% "scala-parser-combinators" % "1.0.4"
)
