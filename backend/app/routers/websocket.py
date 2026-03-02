"""
WebSocket router for real-time analysis updates.
Broadcasts analysis progress to connected clients.
"""

import logging
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
import json
import asyncio

from app.database import get_db, DatabaseOperations
import uuid as uuid_lib

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        """Initialize connection manager."""
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, sample_id: str):
        """
        Connect a client to receive updates for a specific sample.

        Args:
            websocket: WebSocket connection
            sample_id: Sample ID to monitor
        """
        await websocket.accept()

        if sample_id not in self.active_connections:
            self.active_connections[sample_id] = set()

        self.active_connections[sample_id].add(websocket)
        logger.info(f"Client connected for sample {sample_id}")

    def disconnect(self, websocket: WebSocket, sample_id: str):
        """
        Disconnect a client.

        Args:
            websocket: WebSocket connection
            sample_id: Sample ID
        """
        if sample_id in self.active_connections:
            self.active_connections[sample_id].discard(websocket)

            if len(self.active_connections[sample_id]) == 0:
                del self.active_connections[sample_id]

        logger.info(f"Client disconnected from sample {sample_id}")

    async def broadcast(self, sample_id: str, message: dict):
        """
        Broadcast message to all clients monitoring a sample.

        Args:
            sample_id: Sample ID
            message: Message dictionary to broadcast
        """
        if sample_id not in self.active_connections:
            return

        disconnected = set()

        for connection in self.active_connections[sample_id]:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send message: {e}")
                disconnected.add(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.active_connections[sample_id].discard(connection)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/status/{sample_id}")
async def websocket_status(
    websocket: WebSocket, sample_id: str, db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time sample analysis status.

    Args:
        websocket: WebSocket connection
        sample_id: UUID of sample to monitor
        db: Database session
    """
    try:
        # Validate sample ID
        try:
            sample_uuid = uuid_lib.UUID(sample_id)
        except ValueError:
            await websocket.close(code=1003, reason="Invalid sample ID")
            return

        # Check if sample exists
        sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
        if not sample:
            await websocket.close(code=1003, reason="Sample not found")
            return

        # Connect client
        await manager.connect(websocket, sample_id)

        # Send initial status
        initial_status = {
            "type": "initial_status",
            "sample_id": str(sample.id),
            "status": sample.status.value,
            "upload_timestamp": sample.upload_timestamp.isoformat(),
        }
        await websocket.send_json(initial_status)

        # Start periodic status updates
        while True:
            try:
                # Wait for client message or timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)

                # Handle client commands
                if data == "get_status":
                    sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
                    if sample:
                        status_update = {
                            "type": "status_update",
                            "sample_id": str(sample.id),
                            "status": sample.status.value,
                        }

                        # Include analysis results if available
                        if sample.analysis_results:
                            status_update["analysis_results"] = [
                                {
                                    "type": result.analysis_type.value,
                                    "status": result.status.value,
                                }
                                for result in sample.analysis_results
                            ]

                        await websocket.send_json(status_update)

            except asyncio.TimeoutError:
                # Periodic status check
                sample = DatabaseOperations.get_sample_by_id(db, sample_uuid)
                if sample and sample.status.value in ["completed", "failed"]:
                    # Send final status and close
                    final_status = {
                        "type": "final_status",
                        "sample_id": str(sample.id),
                        "status": sample.status.value,
                    }
                    await websocket.send_json(final_status)
                    break

            except WebSocketDisconnect:
                break

    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)

    finally:
        manager.disconnect(websocket, sample_id)


async def notify_status_change(sample_id: str, status: str, progress: int = None):
    """
    Helper function to notify clients of status changes.
    Can be called from Celery tasks.

    Args:
        sample_id: Sample ID
        status: New status
        progress: Optional progress percentage (0-100)
    """
    message = {"type": "status_update", "sample_id": sample_id, "status": status}

    if progress is not None:
        message["progress"] = progress

    await manager.broadcast(sample_id, message)
