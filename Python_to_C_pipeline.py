import joblib
import treelite
import treelite.sklearn
import tl2cgen

rf = joblib.load("randforest_first8.joblib")

# Treelite: load model into Treelite representation
model = treelite.sklearn.import_model(rf)

# TL2cgen: compile/export to a shared library
tl2cgen.export_lib(
    model,
    toolchain="gcc",
    libpath="rf_first8.so",
    params={},      # can be left empty
)

print("Built rf_first8.so")
