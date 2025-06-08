
import uvicorn
from fastapi import FastAPI, Query, Body, Header, Cookie, Form, File, UploadFile
from fastapi.responses import Response, JSONResponse, RedirectResponse
from enum import Enum
from pydantic import BaseModel
from typing import Annotated
from uuid import UUID
from datetime import datetime, date, timedelta, time



app = FastAPI(debug=True)


class ModelName(str, Enum):
    alexnet = "alexnet"
    resnet = "resnet"
    lenet = "lenet"

class Product(BaseModel):
    name: str
    price: float | int
    description: str


@app.post("/product")
async def add_product(product: Product, q: str | None = Query(default="This is the default", min_length=10)):
    print(product.name)
    p = product.model_dump()
    if q:
        p.update({"q": q})
    return p


@app.get("/models/{model_name}")
async def get_model(model_name: ModelName):
    if model_name is ModelName.alexnet:
        return {"model_name": model_name, "message": "Deep Learning FTW!"}

    if model_name.value:
        return {"model_name": model_name, "message": "LeCNN all the images"}
    return {"model_name": model_name, "message": "Have some residuals"}


@app.get("/")
async def main_home():
    return {"message": "Welcome Home Now!"}

@app.get("/items/{item_id}")
async def main_home(item_id: int):
    return {"message": f"Your item id is {item_id}"}



@app.put("/items/{item_id}")
async def read_items(
    item_id: UUID,
    start_datetime: Annotated[datetime, Body()],
    end_datetime: Annotated[datetime, Body()],
    process_after: Annotated[timedelta, Body()],
    repeat_at: Annotated[time | None, Body()] = None,
):
    start_process = start_datetime + process_after
    duration = end_datetime - start_process
    return {
        "item_id": item_id,
        "start_datetime": start_datetime,
        "end_datetime": end_datetime,
        "process_after": process_after,
        "repeat_at": repeat_at,
        "start_process": start_process,
        "duration": duration,
    }



# @app.get("/items/")
# async def read_items(x_token: Annotated[list[str] | None, Header()] = None):
#     return {"X-Token": x_token}


class CommonHeaders(BaseModel):
    host: str
    save_data: bool
    if_modified_since: str | None = None
    traceparent: str | None = None
    x_tag: list[str] = []


@app.get("/items/", response_model=CommonHeaders, response_model_exclude_none=True, response_model_exclude_defaults=True)
async def read_items(
    headers: Annotated[CommonHeaders, Header(convert_underscores=False)],
):
    
    headers.model_dump()    
    
    return headers

@app.get("/portal", response_model=BaseModel)
async def get_portal(teleport: bool = False) -> Response:
    if teleport:
        return RedirectResponse(url="https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    return JSONResponse(content={"message": "Here's your interdimensional portal."})

# if __name__ == "__main__":
#     uvicorn.run(app, host="127.0.0.1", port=5000)


class FormCredentials(BaseModel):
    username: str
    password: str
    model_config = {"extra": "forbid"}


@app.post('/login')
def login_page(data: Annotated[FormCredentials, Form()]):
    return data

@app.post('/uploadfile/')
def upload_file(file: Annotated[bytes, File()]):
    return {"file_size": len(file)}


@app.post('/uploadfile-another/')
def upload_another_file(file: UploadFile):
    return {"file_name": file.filename}
