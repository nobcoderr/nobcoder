from dataclasses import dataclass


@dataclass
class Document:
    owner_id: str
    content: str


def read_document(actor_id: str, document: Document) -> str:
    if actor_id != document.owner_id:
        raise PermissionError("not the owner")
    return document.content
