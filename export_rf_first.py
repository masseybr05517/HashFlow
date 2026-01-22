import joblib
import treelite.sklearn
import tl2cgen

rf = joblib.load("randforest_first8.joblib")
model = treelite.sklearn.import_model(rf)

out_dir = "rf_first8_c"

tl2cgen.generate_c_code(
    model,
    dirpath=out_dir,
    params={}
)

print(f"Generated C code in ./{out_dir}")