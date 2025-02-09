/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package com.lightbend.lagom.scaladsl.persistence.cassandra

import akka.Done
import akka.actor.ActorSystem
import com.datastax.oss.driver.api.core.cql.BoundStatement
import com.datastax.oss.driver.api.core.cql.PreparedStatement
import com.lightbend.lagom.scaladsl.persistence.ReadSideProcessor.ReadSideHandler
import com.lightbend.lagom.scaladsl.persistence.AggregateEventTag
import com.lightbend.lagom.scaladsl.persistence.EventStreamElement
import com.lightbend.lagom.scaladsl.persistence.ReadSideProcessor
import com.lightbend.lagom.scaladsl.persistence.TestEntity

import scala.collection.immutable
import scala.concurrent.Future

object TestEntityReadSide {
  class TestEntityReadSideProcessor(system: ActorSystem, readSide: CassandraReadSide, session: CassandraSession)
      extends ReadSideProcessor[TestEntity.Evt] {
    def buildHandler: ReadSideHandler[TestEntity.Evt] = {
      import system.dispatcher

      @volatile var writeStmt: PreparedStatement = null

      def createTable(): Future[Done] = {
        session.executeCreateTable(
          "CREATE TABLE IF NOT EXISTS testcounts (id text, count bigint, PRIMARY KEY (id))"
        )
      }

      def prepareWriteStmt(): Future[Done] = {
        session.prepare("UPDATE testcounts SET count = ? WHERE id = ?").map { ws =>
          writeStmt = ws
          Done
        }
      }

      def updateCount(element: EventStreamElement[TestEntity.Appended]): Future[immutable.Seq[BoundStatement]] = {
        session.selectOne("SELECT count FROM testcounts WHERE id = ?", element.entityId).map { maybeRow =>
          val count = {
            maybeRow match {
              case Some(row) => row.getLong("count")
              case None      => 0L
            }
          }
          Vector(writeStmt.bind(java.lang.Long.valueOf(count + 1L), element.entityId))
        }
      }

      readSide
        .builder[TestEntity.Evt]("testoffsets")
        .setGlobalPrepare(() => createTable())
        .setPrepare(tag => prepareWriteStmt())
        .setEventHandler[TestEntity.Appended](updateCount)
        .build()
    }

    def aggregateTags: Set[AggregateEventTag[TestEntity.Evt]] = TestEntity.Evt.aggregateEventShards.allTags
  }
}

class TestEntityReadSide(system: ActorSystem, session: CassandraSession) {
  import system.dispatcher

  def getAppendCount(entityId: String): Future[Long] = {
    session.selectOne("SELECT count FROM testcounts WHERE id = ?", entityId).map {
      case Some(row) => row.getLong("count")
      case None      => 0L
    }
  }
}
