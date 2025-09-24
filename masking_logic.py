from faker import Faker
fake = Faker()
MASKING_MAP = {"full_name": fake.name, "name": fake.name, "email": fake.safe_email, "address": fake.address, "phone_number": fake.phone_number, "ssn": fake.ssn}
EXCLUSION_LIST = ["user_id", "id", "guid", "uuid"]
def mask_data_recursively(data):
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            if key in EXCLUSION_LIST: new_dict[key] = value
            elif isinstance(value, (dict, list)): new_dict[key] = mask_data_recursively(value)
            elif key in MASKING_MAP: new_dict[key] = MASKING_MAP[key]()
            else: new_dict[key] = fake.lexify(text='????-????-????')
        return new_dict
    elif isinstance(data, list): return [mask_data_recursively(item) for item in data]
    return data
