from pydantic import BaseModel
from typing import Optional

class RegisterModel(BaseModel):
    id: Optional[int]
    first_name: str
    last_name: str
    username: str
    email: str
    password: str
    is_staff: Optional[bool]
    is_active: Optional[bool]

class LoginModel(BaseModel):
    username: str
    password: str

class CategoryModel(BaseModel):
    id: Optional[int]
    name: str

class ProductModel(BaseModel):
    id: Optional[int]
    name: str
    description: str
    price: float    
    category_id: int


class OrderModel(BaseModel):
    id: Optional[int]
    user_id: int
    product_id: int
    count: int
    order_status: str

class UserOrder(BaseModel):
    username: str


class JwtModel(BaseModel):
    authjwt_secret_key: str = '192ba1860ccd8dcb1577983848289f3792e3c896fd7df9277a773d39d2c9e291'

