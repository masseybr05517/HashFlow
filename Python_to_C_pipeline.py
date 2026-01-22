import joblib
import m2cgen as m2c

rf = joblib.load("randforest_first8.joblib")
print("Loaded object type:", type(rf))
print("Loaded object repr:", rf)
c_code = m2c.export_to_c(rf)

with open("rf_first8_model.c", "w") as f:
    f.write(c_code)
