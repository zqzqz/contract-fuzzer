import setuptools


setuptools.setup(
    name="MythX Trace Finder",
    version="0.0.1",
    author="MythX Development Team",
    packages=[
        "myth_concolic_execution"
    ],
    # ===========================================
    # The entry_points field is used to register the plugin with mythril
    #
    # Right now we register only one plugin for the "mythril.plugins" entry point,
    # note that you can add multiple plugins.
    # ===========================================
    entry_points={
        "mythril.plugins": [
            "myth_concolic_execution = myth_concolic_execution:TraceFinderBuilder",
        ],
    },
    python_requires='>=3.6',
)
