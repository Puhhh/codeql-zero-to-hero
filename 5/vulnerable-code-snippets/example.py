import pickle
import gradio as gr

def load_config_from_file(config_file):
    """Load settings from a UUID.pkl file."""
    try:
        with open(config_file.name, 'rb') as f:
            settings = pickle.load(f)
        return settings
    except Exception as e:
        return f"Error loading configuration: {str(e)}"

with gr.Blocks(title="Configuration Loader") as demo:
    config_file_input = gr.File(label="Load Config File")

    load_config_button = gr.Button("Load Existing Config From File", variant="primary")

    config_status = gr.Textbox(label="Status")

    load_config_button.click(
        fn=load_config_from_file,
        inputs=[config_file_input],
        outputs=[config_status]
    )

demo.launch()
